module Main where

import qualified Data.Maybe as Maybe
import qualified System.Environment as Env
import qualified System.Random as Random
import qualified NumberTheory as NT
import qualified RSA

main :: IO ()
main = do
  g <- Random.newStdGen
  args <- Env.getArgs
  let size = read $ head args :: Integer
  let message = read $ args !! 1 :: Integer
  let key = Maybe.fromJust $ RSA.keygen g size
  let n = RSA.modulus key
  let e = RSA.publicExponent key
  let d = RSA.privateExponent key
  let c = RSA.encrypt message e n
  print $ "cipher text " ++ show c
  let decrypted = RSA.decrypt c d n
  print $ "decrypted " ++ show decrypted
