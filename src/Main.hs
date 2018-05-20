module Main where

import System.Environment
import System.Random
import Primes

main :: IO ()
main = do
    g <- newStdGen
    args <- getArgs
    print $ show $ millerRabin g (read $ head args) (read $ args !! 1)
