import nbformat
from nbconvert.preprocessors import ExecutePreprocessor

# Function to execute cells with the 'test' tag
def run_test_cells(notebook_path):
    # Load the notebook
    with open(notebook_path, 'r') as f:
        nb = nbformat.read(f, as_version=4)

    # Find all cells with the 'test' tag
    test_cells = [cell for cell in nb.cells if 'tags' in cell.metadata and 'test' in cell.metadata['tags']]
    
    # Prepare a new notebook with only the test cells
    test_nb = nbformat.v4.new_notebook()
    test_nb.cells = test_cells

    # Execute the test cells notebook
    ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
    ep.preprocess(test_nb, {'metadata': {'path': './'}})

    # Save the executed notebook (optional)
    with open('executed_test_cells.ipynb', 'w') as f:
        nbformat.write(test_nb, f)

    return test_nb

# Run the function with the current notebook's path
notebook_path = '//Project_Setup_v4.ipynb'
executed_nb = run_test_cells(notebook_path)

# Display executed cells' outputs (optional)
for cell in executed_nb.cells:
    if cell.cell_type == 'code':
        for output in cell.outputs:
            if 'text' in output:
                print(output['text'])