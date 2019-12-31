def transform(app, doctree, fromdocname):
    if "bloomfilter" in fromdocname:
        print("hi")

def transform2(app, doctree):
    print("ok")

def setup(app):
    app.connect('doctree-resolved', transform)
    app.connect('doctree-read', transform2)


    # remove after debug
    # app.connect('builder-inited', add_jinja_filters)

    return {
        'version': '0.1',
        'parallel_read_safe': False,
        'parallel_write_safe': False,
    }