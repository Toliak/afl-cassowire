GIT_ARGS := --progress --depth 1
GIT_ARGS_ADD := 
GIT := git
GIT_CLONE_CMD = $(GIT) clone $(GIT_ARGS) $(GIT_ARGS_ADD)