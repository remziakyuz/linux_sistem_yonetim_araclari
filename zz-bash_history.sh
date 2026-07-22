

    export HISTSIZE=999999
    export HISTFILESIZE=999999
    export HISTTIMEFORMAT="%Y/%h/%d - %H:%M:%S  : "
    export HISTFILE="$HOME/.bash_history-$(date +%Y%m)"

    shopt -s histappend      # kapanista dosyayi ezme, ekle
    shopt -s histreedit
    shopt -s histverify

    # komut biter bitmez HISTFILE'a yaz (anlik/senkron kayit)
    PROMPT_COMMAND="history -a${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
    readonly HISTSIZE HISTFILESIZE HISTTIMEFORMAT HISTFILE PROMPT_COMMAND
