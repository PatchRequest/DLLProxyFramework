from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from analyzer.pe_analyzer import sanitize_identifier

TEMPLATES_DIR = Path(__file__).parent / 'templates'


class TemplateEngine:
    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )
        self.env.filters['sanitize'] = sanitize_identifier
        self.env.filters['quote_def'] = self._quote_def

    @staticmethod
    def _quote_def(name: str) -> str:
        if any(c in name for c in '?@$ <>{}()!#~+-=&*,'):
            return f'"{name}"'
        return name

    def render(self, template_name: str, context: dict) -> str:
        template = self.env.get_template(template_name)
        return template.render(**context)
