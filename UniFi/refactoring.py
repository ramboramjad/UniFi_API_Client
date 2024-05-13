import json


def dumps(obj):
    """ Json dump object
    :param obj:
    :return: json format string of obj
    """
    return json.dumps(obj)


def loads(str):
    """ Load json object
    :param str:
    :return: dict of json objects
    """
    return json.loads(str)


def dumps_loads(obj):
    """ Dumps and loads json object for parsing json response
    :param obj:
    :return: dict of json objects
    """
    obj = json.dumps(obj)
    obj = json.loads(obj)
    return obj


def loads_dumps(obj):
    """ loads and Dumps json object for parsing json response
    :param obj:
    :return: dict of json objects
    """
    obj = json.loads(obj)
    obj = json.dumps(obj)
    return obj
