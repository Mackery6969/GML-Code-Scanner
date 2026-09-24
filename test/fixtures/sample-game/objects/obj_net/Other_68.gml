/// Async - Networking: packets come from other players
var buf = async_load[? "buffer"];
var command = buffer_read(buf, buffer_string);
run_command(command);
