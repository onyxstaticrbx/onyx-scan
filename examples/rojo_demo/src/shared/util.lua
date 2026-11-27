local M = {}
function M.Give(player, amount)
  player.leaderstats.Cash.Value = amount
end
return M
