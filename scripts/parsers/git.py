from models.grammar import CommandSyntax, Flag
from models.parsing import CommandLine, Invocation
from parsers import arguments

GRAMMAR = CommandSyntax(
    aliases=["git"],
    flags=[
        Flag(name="config", keys=["-c"], value_required=True),
        Flag(name="git-dir", keys=["--git-dir", "-C"], value_required=True),
        Flag(name="output", keys=["--output", "-o"], value_required=True),
        Flag(name="version", keys=["--version"], value_required=False),
    ],
    subcommands=[
        # The read-only verbs carry no table of their own: they only need a node so the
        # walk records them in `path` (that is what the analyzer allow-lists against).
        CommandSyntax(aliases=["add"]),
        CommandSyntax(aliases=["check-ignore"]),
        CommandSyntax(aliases=["diff"]),
        CommandSyntax(aliases=["fetch"]),
        CommandSyntax(aliases=["filter-branch"]),
        CommandSyntax(aliases=["grep"]),
        CommandSyntax(aliases=["log"]),
        CommandSyntax(aliases=["ls-files"]),
        CommandSyntax(aliases=["ls-tree"]),
        CommandSyntax(aliases=["merge-base"]),
        CommandSyntax(aliases=["merge-tree"]),
        CommandSyntax(aliases=["rev-list"]),
        CommandSyntax(aliases=["rev-parse"]),
        CommandSyntax(aliases=["show"]),
        CommandSyntax(aliases=["stash"]),
        CommandSyntax(aliases=["status"]),
        CommandSyntax(aliases=["symbolic-ref"]),
        CommandSyntax(aliases=["branch"], flags=[
            Flag(name="all", keys=["--all", "-a"], value_required=False),
            Flag(name="abbrev", keys=["--abbrev", "--no-abbrev"], value_required=False),
            Flag(name="color", keys=["--color", "--no-color"], value_required=False),
            Flag(name="column", keys=["--column", "--no-column"], value_required=False),
            Flag(name="contains", keys=["--contains", "--no-contains"], value_required=False),
            Flag(name="copy", keys=["--copy", "-c", "-C"], value_required=False),
            Flag(name="delete", keys=["--delete", "-d", "-D"], value_required=False),
            Flag(name="format", keys=["--format"], value_required=False),
            Flag(name="list", keys=["--list"], value_required=False),
            Flag(name="merged", keys=["--merged", "--no-merged"], value_required=False),
            Flag(name="points-at", keys=["--points-at"], value_required=False),
            Flag(name="remotes", keys=["--remotes", "-r"], value_required=False),
            Flag(name="show-current", keys=["--show-current"], value_required=False),
            Flag(name="sort", keys=["--sort"], value_required=False),
            Flag(name="verbose", keys=["--verbose", "-v", "-vv"], value_required=False),
        ]),
        # Only the read-only flags/verbs are tabled: every write spelling (`--add`, `--unset`,
        # `--replace-all`, `set`, ...) stays untabled or unlisted so the analyzer sends it to ASK.
        CommandSyntax(aliases=["config"], flags=[
            # Value-taking read flags are value_required=False on purpose: a separate value then
            # lands in the operands (like `git branch --contains HEAD`), which only costs an ASK,
            # while value_required=True would make a bare `--type` a ParseError, hence a DENY.
            Flag(name="default", keys=["--default"], value_required=False),
            Flag(name="file", keys=["--file", "-f"], value_required=True),
            Flag(name="get", keys=["--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool"], value_required=False),
            Flag(name="includes", keys=["--includes", "--no-includes"], value_required=False),
            Flag(name="list", keys=["--list", "-l"], value_required=False),
            Flag(name="name-only", keys=["--name-only"], value_required=False),
            Flag(name="null", keys=["--null", "-z"], value_required=False),
            Flag(name="scope", keys=["--global", "--local", "--system", "--worktree"], value_required=False),
            Flag(name="show-origin", keys=["--show-origin"], value_required=False),
            Flag(name="show-scope", keys=["--show-scope"], value_required=False),
            Flag(name="type", keys=["--type", "-t", "--bool", "--int", "--path"], value_required=False),
        ], subcommands=[
            CommandSyntax(aliases=["get"]),
            CommandSyntax(aliases=["list"]),
            # The write verbs need a node too: without one they would parse as a plain operand,
            # and `git config edit` would look like the single-operand read `git config <name>`.
            CommandSyntax(aliases=["edit"]),
            CommandSyntax(aliases=["remove-section"]),
            CommandSyntax(aliases=["rename-section"]),
            CommandSyntax(aliases=["set"]),
            CommandSyntax(aliases=["unset"]),
        ]),
        CommandSyntax(aliases=["commit"], flags=[
            Flag(name="only", keys=["-o", "--only"], value_required=False),
        ]),
        CommandSyntax(aliases=["push"], flags=[
            Flag(name="force", keys=["--force", "-f"], value_required=False),
        ]),
        CommandSyntax(aliases=["remote"], flags=[
            Flag(name="verbose", keys=["--verbose", "-v"], value_required=False),
        ], subcommands=[
            CommandSyntax(aliases=["add"]),
            CommandSyntax(aliases=["get-url"]),
            CommandSyntax(aliases=["remove", "rm"]),
            CommandSyntax(aliases=["rename"]),
            CommandSyntax(aliases=["set-branches"]),
            CommandSyntax(aliases=["set-head"]),
            CommandSyntax(aliases=["set-url"]),
            CommandSyntax(aliases=["show"]),
            CommandSyntax(aliases=["prune"]),
            CommandSyntax(aliases=["update"]),
        ]),
    ],
)

def parse(command_line:CommandLine) -> Invocation:
    return arguments.parse(command_line=command_line, syntax=GRAMMAR)
