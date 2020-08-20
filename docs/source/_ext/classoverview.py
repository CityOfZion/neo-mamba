from docutils import nodes
from sphinx.util.docutils import SphinxDirective


class ClassOverviewNode(nodes.General, nodes.Element):
    pass


class ClassOverview(SphinxDirective):
    """
    Add a .. classoverview:: directive
    through which we can filter the sidebar with a list of classes discussed in the module
    """
    has_content = True

    def run(self):
        if not hasattr(self.env, 'side_bar_classes'):
            self.env.side_bar_classes = {}

        co_node = ClassOverviewNode()
        co_node._neo3 = self.env.docname

        # this seems to trigger building of partial_xref's, that are resolved by the time
        # the "doctree-resolved" callback is called. Doesn't work without it.
        self.state.nested_parse(self.content, self.content_offset, co_node)

        # we add the node for the time being so we can easily find it when we do the transform step below
        return [co_node]


def transform(app, doctree, fromdocname):
    document_class_links = app.env.side_bar_classes.get(fromdocname, None)

    for n in doctree.traverse(ClassOverviewNode):
        if hasattr(n, '_neo3') and n._neo3 == fromdocname:
            if document_class_links is None:
                app.env.side_bar_classes[fromdocname] = []
            for paragraph in n.children:
                for child in paragraph.children:
                    if isinstance(child, nodes.reference):
                        app.env.side_bar_classes[fromdocname].append(child.attributes['refid'])
            # we don't want to keep the node in the doc that has the directive because it will be moved to the sidebar
            n.parent.remove(n)


def update_context(app, pagename, templatename, context, doctree):
    # Here we update the context passed to our classoverview.html template to include our data
    #
    # This is called before the template is rendered, but after the initial context is filled
    try:
        # for some reason alabaster doesn't have this property, but is part of the default installation.
        docname = context['docname']
    except KeyError:
        return

    # for some unknown reason the dictionary passed to the template cannot be accessed by key inside the template
    # it always throws "UndefinedError" while iterating over the dictionary does work, but that's useless for this use-case
    # we'll just build a list instead which can be accessed by index ¯\_(ツ)_/¯
    list_refids = app.env.side_bar_classes.get(context['docname'], None)
    if list_refids:
        pairs = []
        for refid in list_refids:
            parts = refid.split('.')
            name = parts[-1]
            pairs.append([name, refid])
        pairs.sort(key=lambda pair: pair[0])
        if len(pairs) > 0:
            context['classoverview_links'] = pairs
        else:
            context['classoverview_links'] = None


def purge_classoverview_links(app, env, docname):
    if not hasattr(env, 'side_bar_classes'):
        return

    env.side_bar_classes = {}


def show_all_attrs(value):
    res = []
    for k in dir(value):
        res.append('%r %r\n' % (k, getattr(value, k)))
    return '\n'.join(res)


def add_jinja_filters(app):
    app.builder.templates.environment.filters['dir'] = show_all_attrs


def setup(app):
    app.add_node(ClassOverviewNode),
    app.add_directive('classoverview', ClassOverview)
    app.connect('doctree-resolved', transform)
    app.connect('html-page-context', update_context)
    app.connect('env-purge-doc', purge_classoverview_links)

    # remove after debug
    # app.connect('builder-inited', add_jinja_filters)

    return {
        'version': '0.1',
        'parallel_read_safe': False,
        'parallel_write_safe': False,
    }