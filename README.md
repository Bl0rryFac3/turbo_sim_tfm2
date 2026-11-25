# Turbo Sim

Turbo Sim speeds up calendar advances in Teamfight Manager 2. I made it because simming with a big champion roster was taking forever on my laptop.

It speeds up background matches between two AI teams in Simple mode. The AI picks randomly from the champions it can legally pick, which saves the time it normally spends figuring out the best pick. Pick, ban, and Fearless rules still apply, and matches involving your team use normal drafts.

Background AI drafts can be less strategic, so match results and standings can change. In my 0.7.3 test with 275 champions, the same advance went from **6 minutes 20 seconds to 31.6 seconds**. Times vary by save and PC.

## Install

1. Close the game. If you have an older Turbo Sim or Faster Days install, move its folder out of `mods` first.
2. Extract the ZIP and put the `Turbo_Sim` folder inside the game's `mods` folder.
3. Open the game, enable **Turbo Sim** in the Mods menu, and restart. Set **Simulation Intensity** to **Simple**.

Turbo Sim 1.0.1 is for Teamfight Manager 2 **0.7.4 on Windows**. Turbo is on by default. To keep faster Simple simulation with normal AI drafts, close the game, set `mods/Turbo_Sim/turbo.txt` to `off`, keep `enabled.txt` set to `on`, and restart.
