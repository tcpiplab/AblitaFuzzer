import markdown
from bs4 import BeautifulSoup

def convert_markdown_to_html_with_collapsible_sections(markdown_text):
    # Convert Markdown to HTML
    html = markdown.markdown(markdown_text)

    # Parse the HTML with BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')

    # Add collapsible functionality to headers
    for header in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']):
        content = []
        sibling = header.find_next_sibling()
        while sibling and sibling.name not in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
            content.append(sibling)
            sibling = sibling.find_next_sibling()

        # Wrap content in a collapsible div
        div = soup.new_tag('div', **{'class': 'collapsible-content'})
        for element in content:
            div.append(element.extract())

        header.insert_after(div)

        # Add a button to the header to toggle the collapsible content
        button = soup.new_tag('button', **{'class': 'collapsible-button'})
        button.string = 'Toggle'
        header.insert_after(button)

    # Add CSS and JavaScript for collapsible functionality
    style = """
    <style>
        .collapsible-content { display: none; }
        .collapsible-button { margin: 5px 0; cursor: pointer; }
    </style>
    """
    script = """
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            var buttons = document.querySelectorAll('.collapsible-button');
            buttons.forEach(function(button) {
                button.addEventListener('click', function() {
                    var content = this.nextElementSibling;
                    if (content.style.display === 'block') {
                        content.style.display = 'none';
                    } else {
                        content.style.display = 'block';
                    }
                });
            });
        });
    </script>
    """
    soup.append(BeautifulSoup(style, 'html.parser'))
    soup.append(BeautifulSoup(script, 'html.parser'))

    return str(soup)

# Example usage
markdown_text = """
# Header 1
Content under header 1.

## Header 2
Content under header 2.

### Header 3
Content under header 3.
"""

html_with_collapsible_sections = convert_markdown_to_html_with_collapsible_sections(markdown_text)

# Write to an HTML file
with open('output.html', 'w') as file:
    file.write(html_with_collapsible_sections)