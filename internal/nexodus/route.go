package nexodus

import "fmt"

func AddChildPrefixRoute(childPrefix string, tunnelIface string) error {

	routeExists, err := RouteExists(childPrefix)
	if err != nil {
		return err
	}

	if !routeExists {
		if err := AddRoute(childPrefix, tunnelIface); err != nil {
			return fmt.Errorf("error adding the child prefix route: %w", err)
		}
	}
	return nil
}
