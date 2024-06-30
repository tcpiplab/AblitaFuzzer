import nbformat
from nbconvert import PythonExporter

def convert_notebook_to_script(notebook_path, script_path):
    with open(notebook_path) as f:
        nb = nbformat.read(f, as_version=4)
    exporter = PythonExporter()
    script, _ = exporter.from_notebook_node(nb)
    with open(script_path, 'w') as f:
        f.write(script)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Convert Jupyter Notebook to Python script.')
    parser.add_argument('notebook_path', type=str, help='Path to the Jupyter Notebook file')
    parser.add_argument('script_path', type=str, help='Path to save the converted Python script')
    args = parser.parse_args()
    convert_notebook_to_script(args.notebook_path, args.script_path)
