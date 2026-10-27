# BUILD THE ALGOBANK DEX
# run in site/:  python run.py
# needs dexweb; algobank it and everything it calls first (see the Usage page)

import shutil
from dexweb import dexgen

dex = dexgen.Dexgen()                                       # data.json + config.json + styles.css -> gen/
shutil.copytree("assets", "gen/assets", dirs_exist_ok=True)  # the Italiana font: dexgen copies only styles.css
