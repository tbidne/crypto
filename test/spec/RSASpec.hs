module RSASpec
( spec
)
where

import Data.ByteString.Lazy (ByteString, unpack, writeFile)
import Data.Maybe (fromJust, isNothing)
import System.Process (callCommand)
import System.Random (newStdGen)
import Test.Hspec

import qualified RSA

spec :: Spec
spec = do
  describe "keygen" $ do
    it "should generate 1024 bit key" $ do
      keygen 1024 135 260

    it "should generate 2048 bit key" $ do
      keygen 2048 263 516

    it "should generate 4096 bit key" $ do
      keygen 4096 519 1028

    it "should return Nothing for wrong bit key" $ do
      g <- newStdGen
      let key = RSA.keygen g 1000
      isNothing key `shouldBe` True

keygen :: Int -> Int -> Int -> Expectation
keygen sizeInBits expectedPk expectedSk = do
  g <- newStdGen
  let key = RSA.keygen g sizeInBits
  let (pk, sk) = fromJust key
  let pkLen = length $ unpack pk
  let skLen = length $ unpack sk
  pkLen `shouldSatisfy` (\x -> x `elem` [expectedPk-1..expectedPk+1])
  skLen `shouldSatisfy` (\x -> x `elem` [expectedSk-1..expectedSk+1])