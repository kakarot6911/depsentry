"""Response rendering -- reaches the Jinja2 sandbox-escape advisory."""

import jinja2


def render_summary(template_text, context):
    env = jinja2.Environment()
    return env.from_string(template_text).render(**context)
