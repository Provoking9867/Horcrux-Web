/*
 * diceware.js — EFF Large Wordlist for Diceware passphrases
 * ==========================================================
 * Wordlist is embedded in eff_wordlist.js (loaded before this file).
 * Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
 */

function lookupWord(roll) {
  if (!/^[1-6]{5}$/.test(roll)) throw new Error(`Invalid roll '${roll}': use 5 digits 1-6.`);
  if (typeof _WL === 'undefined') throw new Error('Wordlist not loaded. Ensure eff_wordlist.js is included before diceware.js.');
  if (!(roll in _WL)) throw new Error(`Roll ${roll} not found in wordlist.`);
  return _WL[roll];
}

if (typeof window !== 'undefined') {
  window.Diceware = { lookupWord };
}
