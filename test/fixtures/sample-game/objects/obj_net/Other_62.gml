/// Async - HTTP
if (async_load[? "id"] != scores_request) exit;
var data = json_parse(async_load[? "result"]);
file_delete(data.slot + ".sav");
variable_instance_set(id, data.key, data.value);
