module Primes
( genPrime
, millerRabin
) where

import System.Random

genPrime :: (RandomGen a, Integral b) => a -> b -> Integer
genPrime g size
  | millerRabin g n 10 = n
  | otherwise          = genPrime g' size
  where rand = randomR(2^(size-1), 2^size - 1) g
        n = fst rand
        g' = snd rand

-- returns true if n is probably prime, false if definitely composite
--
-- g <- newStdGen
-- n = number tested for primality
-- k = number of trials, must be > 0
millerRabin :: (RandomGen a, Integral b) => a -> Integer -> b -> Bool
millerRabin _ _ 0 = True
millerRabin g n k
  | even n        = False
  | isWitness a n = False
  | otherwise     = millerRabin g' n (k-1)
  where rand = randomR(2, n-2) g
        a = fst rand
        g' = snd rand 

-- returns true if a is a witness for a being composite, false otherwise
--
-- a in [2, n-2]
-- n = integer to test
isWitness :: Integral a => a -> a -> Bool
isWitness a n
  | x == 1 || x == n-1 = False
  | otherwise          = checkPowers (r-1) x n
  where factors = factor(n-1)
        r = fst factors
        d = snd factors
        x = powModN a d n

-- returns true if any of x, x^2, x^4, ... are witnesses to n being composite,
-- false otherwise
--
-- i = counter for how many times we square x
-- x = potential witness
-- n = number to test
checkPowers :: Integral a => a -> a -> a -> Bool
checkPowers 0 _ _ = True
checkPowers i x n
  | y == 1    = True
  | y == n-1  = False
  | otherwise = checkPowers (i-1) y n
  where y = (x*x) `mod` n


-- returns (r, d) where 2^r * d = n
factor :: Integral a => a -> (a, a)
factor n =
  let r = maxPowTwoDivisor n 1
      d = n `div` (2^r)
  in (r, d)

-- returns the highest power of two that divides n
maxPowTwoDivisor :: Integral a => a -> a -> a
maxPowTwoDivisor n i
  | 2^i * d /= n = i-1
  | otherwise    = maxPowTwoDivisor n (i+1)
  where d = n `div` (2^i)

-- returns a^d mod n
powModN :: Integral a => a -> a -> a -> a
powModN a 1 n = a
powModN a d n = (a^(d `mod` 2) * powModN (a*a `mod` n) (d `div` 2) n) `mod` n