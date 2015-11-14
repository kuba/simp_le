import collections
import json
import pkg_resources

def dump_entry_points(tmp_entry_points_path, *distribution_names):
    """Dump entry points database.

    Compile a database by going through all entry points registered by
    distributions listed in `distribution_names`. Serialize database to
    JSON and dump to a file (located in `tmp_entry_points_path`) that
    can be later copied to the one-folder/one-file distribution and used
    by `rthook-entrypoints.iter_entry_points`.

    """
    entry_points = collections.defaultdict(collections.defaultdict)
    for name in distribution_names:
        entry_map = pkg_resources.get_distribution(name).get_entry_map()
        for group, eps in entry_map.iteritems():
            entry_points[group][name] = [str(ep) for ep in eps.itervalues()]
    with open(tmp_entry_points_path, 'w') as fp:
        fp.write(json.dumps(entry_points))
    return entry_points
