Output docs/assets/phantom-secrets-demo.gif
Set Shell bash
Set FontSize 16
Set Width 1100
Set Height 640
Set Theme "Catppuccin Mocha"
Hide
Type 'cd $(mktemp -d) && printf "OPENAI_API_KEY=sk-proj-9f2kXq7realsecret\nSTRIPE_SECRET_KEY=sk_live_51Hreal\n" > .env && PS1="$ " && clear' Enter
Show
Type "cat .env   # real keys an AI agent could read" Sleep 400ms Enter
Sleep 2s
Type "phantom init" Sleep 400ms Enter
Sleep 3s
Type "clear && cat .env   # now only phm_ tokens" Sleep 400ms Enter
Sleep 2s
Type "phantom list" Sleep 400ms Enter
Sleep 3s
