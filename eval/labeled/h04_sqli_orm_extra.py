def search(Model, term):
    return Model.objects.extra(where=[f"name = '{term}'"])  # KLABEL CWE-89
