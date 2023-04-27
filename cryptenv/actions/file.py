import argparse


class FileAction(argparse.Action):

    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is None or nargs != argparse.OPTIONAL:
            raise ValueError(f"Expected nargs='{argparse.OPTIONAL}' for {option_strings[0]} option")

        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)

        if not namespace.file.is_file():
            print(f"File not found: {namespace.file.resolve()}")
