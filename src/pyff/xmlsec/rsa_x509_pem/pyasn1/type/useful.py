# ASN.1 "useful" types
from . import char, tag

class GeneralizedTime(char.VisibleString):
    tagSet = char.VisibleString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 24)
        )

class UTCTime(char.VisibleString):
    tagSet = char.VisibleString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 23)
        )
