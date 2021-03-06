module AES.APISpec
( spec
)
where

import Data.ByteString.Lazy (unpack)
import Data.Maybe (fromJust, isNothing)
import System.Random (newStdGen)
import Test.Hspec

import qualified AES.API as AES

spec :: Spec
spec = do
  describe "keygen" $ do
    it "should generate 128 bit key" $ do
      keygen 128 16
    
    it "should generate 192 bit key" $ do
      keygen 192 24

    it "should generate 256 bit key" $ do
      keygen 256 32

    it "should return Nothing for wrong bit key" $ do
      g <- newStdGen
      let key = AES.keygen g 100
      isNothing key `shouldBe` True

keygen :: Int -> Int -> Expectation
keygen sizeInBits expectedBytes = do
  g <- newStdGen
  let key = AES.keygen g sizeInBits
  let k = unpack $ fromJust key
  length k `shouldBe` expectedBytes