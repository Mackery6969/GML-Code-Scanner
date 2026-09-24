/// @param {Array<Real>} values
function sum_all(values) {
    var total = 0;
    array_foreach(values, function(v) {
        total += v; // GML has no closures: not the local `total`
    });
    return total;
}

/// @param {String} name
function run_command(name) {
    script_execute(asset_get_index(name));
}

function never_called() {
    return 42;
}
