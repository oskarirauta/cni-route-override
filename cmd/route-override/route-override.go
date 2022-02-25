// Copyright 2019 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is a "meta-plugin". It reads in its own netconf, it does not create
// any network interface but just changes route information given from
// previous cni plugins

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/vishvananda/netlink"
)

// Todo:
// + only checko route/dst
//go build ./cmd/route-override/

// from containernetworking/cni/pkg/types

type Route2 struct {
	Dst net.IPNet
	GW  net.IP
	Via net.IP
	Src net.IP
}

func (r *Route2) String() string {
	return fmt.Sprintf("%+v", *r)
}

func (r *Route2) Legacy() types.Route {
	return types.Route{
		Dst: r.Dst,
		GW:  r.GW,
	}
}

type route2 struct {
	Dst types.IPNet `json:"dst"`
	GW  net.IP      `json:"gw,omitempty"`
	Via net.IP      `json:"via,omitempty"`
	Src net.IP      `json:"src,omitempty"`
}

func (r *route2) Legacy() types.Route {
	return types.Route{
		Dst: net.IPNet(r.Dst),
		GW:  r.GW,
	}
}

func (r *Route2) UnmarshalJSON(data []byte) error {
	rt := route2{}
	if err := json.Unmarshal(data, &rt); err != nil {
		return err
	}

	r.Dst = net.IPNet(rt.Dst)
	r.GW = rt.GW
	r.Via = rt.Via
	r.Src = rt.Src
	return nil
}

func (r Route2) MarshalJSON() ([]byte, error) {
	rt := route2{
		Dst: types.IPNet(r.Dst),
		GW:  r.GW,
		Via: r.Via,
		Src: r.Src,
	}

	return json.Marshal(rt)
}

// RouteOverrideConfig represents the network route-override configuration
type RouteOverrideConfig struct {
	types.NetConf

	PrevResult *current.Result `json:"-"`

	FlushRoutes  bool           `json:"flushroutes,omitempty"`
	FlushGateway bool           `json:"flushgateway,omitempty"`
	DelRoutes    []*route2      `json:"delroutes"`
	AddRoutes    []*route2      `json:"addroutes"`
	SkipCheck    bool           `json:"skipcheck,omitempty"`

	Args *struct {
		A *IPAMArgs `json:"cni"`
	} `json:"args"`
}

// IPAMArgs represents CNI argument conventions for the plugin
type IPAMArgs struct {
	FlushRoutes  *bool          `json:"flushroutes,omitempty"`
	FlushGateway *bool          `json:"flushgateway,omitempty"`
	DelRoutes    []*route2      `json:"delroutes,omitempty"`
	AddRoutes    []*route2      `json:"addroutes,omitempty"`
	SkipCheck    *bool          `json:"skipcheck,omitempty"`
}

/*
type RouteOverrideArgs struct {
	types.CommonArgs
}
*/
func parseConf(data []byte, envArgs string) (*RouteOverrideConfig, error) {
	conf := RouteOverrideConfig{FlushRoutes: false}

	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	// override values by args
	if conf.Args != nil {
		if conf.Args.A.FlushRoutes != nil {
			conf.FlushRoutes = *conf.Args.A.FlushRoutes
		}

		if conf.Args.A.FlushGateway != nil {
			conf.FlushGateway = *conf.Args.A.FlushGateway
		}

		if conf.Args.A.DelRoutes != nil {
			conf.DelRoutes = conf.Args.A.DelRoutes
		}

		if conf.Args.A.AddRoutes != nil {
			conf.AddRoutes = conf.Args.A.AddRoutes
		}

		if conf.Args.A.SkipCheck != nil {
			conf.SkipCheck = *conf.Args.A.SkipCheck
		}

	}

	// Parse previous result
	if conf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(conf.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}

		res, err := version.NewResult(conf.CNIVersion, resultBytes)

		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}

		conf.RawPrevResult = nil
		conf.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	return &conf, nil
}

func deleteAllRoutes(res *current.Result) error {
	var err error
	for _, netif := range res.Interfaces {
		if netif.Sandbox != "" {
			link, _ := netlink.LinkByName(netif.Name)
			routes, _ := netlink.RouteList(link, netlink.FAMILY_ALL)
			for _, route := range routes {
				if route.Scope != netlink.SCOPE_LINK {
					if route.Dst != nil {
						if route.Dst.IP.IsLinkLocalUnicast() != true && route.Gw != nil {
							err = netlink.RouteDel(&route)
						}
					} else {
						err = netlink.RouteDel(&route)
					}
				}
			}
		}
	}

	return err
}

func deleteGWRoute(res *current.Result) error {
	var err error
	// fallback to eth0 if there is no interface in result
	if res.Interfaces == nil {
		link, _ := netlink.LinkByName("eth0")
		routes, _ := netlink.RouteList(link, netlink.FAMILY_ALL)
		for _, nlroute := range routes {
			if nlroute.Dst == nil {
				err = netlink.RouteDel(&nlroute)
			}
		}
	} else {
		for _, netif := range res.Interfaces {
			if netif.Sandbox != "" {
				link, _ := netlink.LinkByName(netif.Name)
				routes, _ := netlink.RouteList(link, netlink.FAMILY_ALL)
				for _, nlroute := range routes {
					if nlroute.Dst == nil {
						err = netlink.RouteDel(&nlroute)
					}
				}
			}
		}
	}

	return err
}

func deleteRoute(route *route2, res *current.Result) error {
	var err error
	// fallback to eth0 if there is no interface in result
	if res.Interfaces == nil {
		link, _ := netlink.LinkByName("eth0")
		routes, _ := netlink.RouteList(link, netlink.FAMILY_ALL)
		for _, nlroute := range routes {
			if nlroute.Dst != nil &&
				nlroute.Dst.IP.Equal(route.Dst.IP) &&
				nlroute.Dst.Mask.String() == route.Dst.Mask.String() {

				var mismatch bool

				if ( route.Via != nil ) {

					via := netlink.Via {
						AddrFamily: netlink.FAMILY_V4,
						Addr:       route.Via,
					}

					if (( nlroute.Via != nil && via.Equal(nlroute.Via)) || nlroute.Via == nil ) {
						mismatch = true
					}
				}

				if (( nlroute.Src != nil && !nlroute.Src.Equal(route.Src)) ||
				    ( nlroute.Src == nil && route.Src != nil )) {
					mismatch = true
				}

				if ( !mismatch ) {
					err = netlink.RouteDel(&nlroute)
				}
			}
		}
	} else {
		for _, netif := range res.Interfaces {
			if netif.Sandbox != "" {
				link, _ := netlink.LinkByName(netif.Name)
				routes, _ := netlink.RouteList(link, netlink.FAMILY_ALL)
				for _, nlroute := range routes {
					if nlroute.Dst != nil &&
						nlroute.Dst.IP.Equal(route.Dst.IP) &&
						nlroute.Dst.Mask.String() == route.Dst.Mask.String() {

						var mismatch bool

						if ( route.Via != nil ) {

							via := netlink.Via {
							AddrFamily: netlink.FAMILY_V4,
							Addr:       route.Via,
							}

							if (( nlroute.Via != nil && via.Equal(nlroute.Via)) || nlroute.Via == nil ) {
								mismatch = true
							}
						}

						if (( nlroute.Src != nil && !nlroute.Src.Equal(route.Src)) ||
						    ( nlroute.Src == nil && route.Src != nil )) {
							mismatch = true
						}

						if ( !mismatch ) {
							err = netlink.RouteDel(&nlroute)
						}
					}
				}
			}
		}
	}

	return err
}

func addRoute(dev netlink.Link, route *route2) error {

	fmt.Fprintf(os.Stderr, "adding route index: %v, dst: %v, gw: %v, src: %v, via: %v", dev.Attrs().Index, route.Dst, route.GW, route.Src, route.Via)

	var multipath []*netlink.NexthopInfo
	var via *netlink.Via
	var via2 netlink.Via

	if err := netlink.LinkSetUp(dev); err != nil {
		fmt.Fprintf(os.Stderr, "error bringing link up while adding route: %v", err)
	}

	if ( route.Via != nil ) {

		via2 = netlink.Via {
			AddrFamily: 	netlink.FAMILY_V4,
			Addr:		route.Via,
		}

		via = &via2;

		multipath = []*netlink.NexthopInfo {
			{
			LinkIndex: dev.Attrs().Index,
			Via:	   via,
			},
		}

	}

	dst := net.IPNet(route.Dst)

	newRoute := &netlink.Route {
		LinkIndex:	dev.Attrs().Index,
		Scope:		netlink.SCOPE_UNIVERSE,
		Dst:		&dst,
		Gw:		route.GW,
		Src:		route.Src,
		MultiPath:	multipath,
		Via:		via,
	}
/*
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: dev.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       &route.Dst,
		Gw:        route.GW,
		Via:       route.Via,
		Src:       route.Src,
	})
*/

	return netlink.RouteAdd(newRoute)
}

func processRoutes(netnsname string, conf *RouteOverrideConfig) (*current.Result, error) {
	netns, err := ns.GetNS(netnsname)
	if err != nil {
		return nil, fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	res, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return nil, fmt.Errorf("could not convert result to current version: %v", err)
	}

	if conf.FlushGateway {
		// add "0.0.0.0/0" into delRoute to remove it from routing table/result
		_, gwRoute, _ := net.ParseCIDR("0.0.0.0/0")
		gwRoute2 := types.IPNet{
			IP:   gwRoute.IP,
			Mask: gwRoute.Mask,
		}
		conf.DelRoutes = append(conf.DelRoutes, &route2{Dst: gwRoute2})
		_, gwRoute, _ = net.ParseCIDR("::/0")
		gwRoute3 := types.IPNet{
			IP:   gwRoute.IP,
			Mask: gwRoute.Mask,
		}
		conf.DelRoutes = append(conf.DelRoutes, &route2{Dst: gwRoute3})

		// delete given gateway address
		for _, ips := range res.IPs {
			if ips.Version == "6" {
				ips.Gateway = net.IPv6zero
			} else {
				ips.Gateway = net.IPv4zero
			}
		}
	}

	newRoutes := []*types.Route{}

	err = netns.Do(func(_ ns.NetNS) error {
		// Flush route if required
		if !conf.FlushRoutes {
		NEXT:
			for _, route := range res.Routes {
				for _, delroute := range conf.DelRoutes {
					if route.Dst.IP.Equal(delroute.Dst.IP) &&
						bytes.Equal(route.Dst.Mask, delroute.Dst.Mask) {

						err = deleteRoute(delroute, res)
						if err != nil {
							fmt.Fprintf(os.Stderr, "failed to delete route %v: %v", delroute, err)
						}

						continue NEXT
					}

				}
				newRoutes = append(newRoutes, route)
			}
		} else {
			deleteAllRoutes(res)
		}

		if conf.FlushGateway {
			deleteGWRoute(res)
		}

		// Get container IF name
		var containerIFName string
		for _, i := range res.Interfaces {
			if i.Sandbox != "" {
				containerIFName = i.Name
				break
			}
		}
		// Add route
		dev, _ := netlink.LinkByName(containerIFName)
		for _, route := range conf.AddRoutes {

			legacyroute := route.Legacy()
			newRoutes = append(newRoutes, &legacyroute)

			if err := addRoute(dev, route); err != nil {
				fmt.Fprintf(os.Stderr, "failed to add route: %v: %v", route, err)
			}
		}

		return nil
	})
	res.Routes = newRoutes

	return res, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	overrideConf, err := parseConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	newResult, err := processRoutes(args.Netns, overrideConf)
	if err != nil {
		return fmt.Errorf("failed to override routes: %v", err)
	}

	return types.PrintResult(newResult, overrideConf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// TODO: the settings are not reverted to the previous values. Reverting the
	// settings is not useful when the whole container goes away but it could be
	// useful in scenarios where plugins are added and removed at runtime.
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	// Parse previous result
	overrideConf, err := parseConf(args.StdinData, args.Args)

	if err != nil {
		return err
	}

	// if skipcheck is true, skip it
	if overrideConf.SkipCheck == true {
		return nil
	}

	if overrideConf.PrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(&overrideConf.NetConf); err != nil {
		return err
	}

	result, err := current.NewResultFromResult(overrideConf.PrevResult)
	if err != nil {
		return err
	}

	gateways := []net.IP{}
	for _, i := range result.IPs {
		gateways = append(gateways, i.Gateway)
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		for _, cniRoute := range overrideConf.DelRoutes {
			_, err := netlink.RouteGet(cniRoute.Dst.IP)
			if err == nil {
				return fmt.Errorf("route-override: route is not removed: %v", cniRoute)
			}
		}

		for _, cniRoute := range result.Routes {
			var routes []netlink.Route
			if cniRoute.Dst.IP.Equal(net.ParseIP("0.0.0.0")) == true || cniRoute.Dst.IP.Equal(net.ParseIP("::")) {
				family := netlink.FAMILY_ALL
				if cniRoute.Dst.IP.To4() == nil {
					family = netlink.FAMILY_V6
				} else {
					family = netlink.FAMILY_V4
				}
				filter := &netlink.Route{
					Dst: nil,
				}
				routes, err = netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST)
				if err != nil {
					return err
				}
			} else {
				routes, err = netlink.RouteGet(cniRoute.Dst.IP)
				if err != nil {
					return err
				}
			}

			if len(routes) != 1 {
				return fmt.Errorf("route-override: got multiple routes: %v", routes)
			}

			// if gateway in cni result is nil, then lookup gateways in interface of cni result
			if cniRoute.GW == nil {
				found := false
				for _, gw := range gateways {
					if gw.Equal(routes[0].Gw) {
						found = true
					}
				}
				if found != true {
					return fmt.Errorf("route-override: cannot find gateway %v in result: %v", cniRoute.GW, routes[0].Gw)
				}
			} else {
				if routes[0].Gw.Equal(cniRoute.GW) != true {
					return fmt.Errorf("route-override: failed to match route: %v %v", cniRoute, routes[0].Gw)
				}
			}
		}
		return nil
	})

	return err
}

func main() {
	// TODO: implement plugin version
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, "TODO")
}
