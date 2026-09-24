draw_self();
draw_text(x, y - 32, "HP: " + hp);          // crashes: string + number
draw_text(x, y - 48, "Speed: " + string(move_speed));

// Surfaces can be lost at any time
surface_set_target(surf);
draw_clear_alpha(c_black, 0);
surface_reset_target();
draw_surface(surf, 0, 0);
