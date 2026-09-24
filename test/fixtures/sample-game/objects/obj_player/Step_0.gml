x += move_sped; // typo

// Reset every step, so the alarm never fires
alarm[0] = 60;

// Stray semicolon: the jump always happens
if (keyboard_check_pressed(vk_space)); {
    y -= 8;
}

// Drawing in Step has no visible effect
draw_text(x, y - 16, "Player");

var total = sum_all(scores);
if (instance_number(obj_net) > 0) {
    show_debug_message("online");
}
