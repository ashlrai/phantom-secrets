# Shell Prompt Integration

Show Phantom status in your shell prompt so you always know if secrets are protected.

## Starship

Add to `~/.config/starship.toml`:

```toml
[custom.phantom]
command = "phantom status --oneline 2>/dev/null"
when = "test -f .phantom.toml"
format = "[$output]($style) "
style = "dimmed white"
```

This shows something like: `3 secrets · proxy off`

## Zsh

Add to `~/.zshrc`:

```bash
phantom_status() {
  if [ -f .phantom.toml ]; then
    local status=$(phantom status --oneline 2>/dev/null)
    [ -n "$status" ] && echo " [phm:$status]"
  fi
}
PROMPT='%~ $(phantom_status)%# '
```

## Bash

Add to `~/.bashrc`:

```bash
phantom_status() {
  if [ -f .phantom.toml ]; then
    local status=$(phantom status --oneline 2>/dev/null)
    [ -n "$status" ] && echo " [phm:$status]"
  fi
}
PS1='\w$(phantom_status)\$ '
```

## Oh My Zsh (custom plugin)

Create `~/.oh-my-zsh/custom/plugins/phantom/phantom.plugin.zsh`:

```bash
phantom_prompt_info() {
  if [ -f .phantom.toml ]; then
    echo " %{$fg[white]%}[phm:$(phantom status --oneline 2>/dev/null)]%{$reset_color%}"
  fi
}
RPROMPT='$(phantom_prompt_info)'
```

Then add `phantom` to your plugins in `~/.zshrc`:
```bash
plugins=(git phantom)
```
