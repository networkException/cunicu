## wicectl completion powershell

Generate the autocompletion script for powershell

### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	wicectl completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
wicectl completion powershell [flags]
```

### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --config string   Path to config file (default $HOME/.wice.yaml)
      --socket string   Unix control and monitoring socket (default "/var/run/wice.sock")
```

### SEE ALSO

* [wicectl completion](wicectl_completion.md)	 - Generate the autocompletion script for the specified shell

###### Auto generated by spf13/cobra on 6-Jan-2022