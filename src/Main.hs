module Main where

import System.Environment
import System.Random
import Primes

main :: IO ()
main = do
    g <- newStdGen
    args <- getArgs
    print $ show $ genPrime g (read $ head args)
