package main

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/stv0g/cunicu/pkg/config"
	rpcproto "github.com/stv0g/cunicu/pkg/proto/rpc"
)

var (
	configCmd = &cobra.Command{
		Use:   "config",
		Short: "Manage runtime configuration",
	}

	setCmd = &cobra.Command{
		Use:               "set key value",
		Short:             "Update the value of a configuration setting",
		Run:               set,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: validConfigSettings,
	}

	getCmd = &cobra.Command{
		Use:               "get key",
		Short:             "Get current value of a configuration setting",
		Run:               get,
		Args:              cobra.RangeArgs(0, 1),
		ValidArgsFunction: validConfigSettings,
	}
)

func init() {
	addClientCommand(rootCmd, configCmd)
	configCmd.AddCommand(setCmd)
	configCmd.AddCommand(getCmd)
}

func getCompletions(typ reflect.Type, haveCompleted, toComplete string) ([]string, cobra.ShellCompDirective) {
	tagComplete := strings.Split(toComplete, ".")[0]

	flags := cobra.ShellCompDirectiveNoFileComp
	fields := []reflect.StructField{}
	comps := []string{}
	structComps := []string{}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tagLine := field.Tag.Get("yaml")
		comp := strings.Split(tagLine, ",")[0]

		if strings.HasPrefix(comp, tagComplete) {
			if field.Type.Kind() == reflect.Struct {
				comp += "."
				flags |= cobra.ShellCompDirectiveNoSpace

				structComps = append(structComps, comp)
			}

			fields = append(fields, field)
			comps = append(comps, haveCompleted+comp)
		}
	}

	if len(fields) == 1 && fields[0].Type.Kind() == reflect.Struct {
		if strings.HasPrefix(toComplete, structComps[0]) {
			toComplete = strings.TrimPrefix(toComplete, structComps[0])
		} else {
			toComplete = ""
		}

		return getCompletions(fields[0].Type, haveCompleted+structComps[0], toComplete)
	}

	return comps, flags
}

func validConfigSettings(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	t := reflect.TypeOf(config.Settings{})

	return getCompletions(t, "", toComplete)
}

func set(cmd *cobra.Command, args []string) {
	settings := map[string]string{
		args[0]: args[1],
	}

	if _, err := rpcClient.SetConfig(context.Background(), &rpcproto.SetConfigParams{
		Settings: settings,
	}); err != nil {
		logger.Fatal("Failed to set configuration", zap.Error(err))
	}
}

func get(cmd *cobra.Command, args []string) {
	params := &rpcproto.GetConfigParams{}

	if len(args) > 0 {
		params.KeyFilter = args[0]
	}

	resp, err := rpcClient.GetConfig(context.Background(), params)
	if err != nil {
		logger.Fatal("Failed to set configuration", zap.Error(err))
	}

	keys := maps.Keys(resp.Settings)
	slices.Sort(keys)

	for _, key := range keys {
		fmt.Printf("%s\t%s\n", key, resp.Settings[key])
	}
}