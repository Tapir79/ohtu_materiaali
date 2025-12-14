# tähän luokkaan ei tehtävässä välttämättä kiinniteltä huomiota, eli luokka on kutakuinkin ok koodiltaan

class Kirja:
    def __init__(self, kirjoittaja, nimi, id, lainassa=False):
        self.kirjoittaja = kirjoittaja
        self.nimi = nimi
        self.lainassa = lainassa
        self.id = id

    def __str__(self):
        if self.lainassa:
            status = "lainassa"
        else:
            status = "ei lainassa"
        return f"[{self.id}] {self.kirjoittaja}: {self.nimi} ({status})"

# tehtävässä tarkastaltava luokka

class Kirjasto:
    def __init__(self):
        self.__kirjat = []
        self.__id = 1

        try:
          with open("tiedosto.csv") as tiedosto:
            for rivi in tiedosto:
                  osat = rivi.rstrip().split(";")
                  id = int(osat[0])
                  kirja = Kirja(osat[1], osat[2], id, osat[3]=='True')
                  self.__kirjat.append(kirja)
            max_id = 0
            for kirja in self.__kirjat:
                    if kirja.id > max_id:
                        max_id = kirja.id
            self.__id = max_id +1
        except:
            pass

    def lisaa(self, kirjoittaja, nimi):
        kirja = Kirja(kirjoittaja, nimi, self.__id)
        self.__id += 1
        self.__kirjat.append(kirja)

        with open("tiedosto.csv", "w") as tiedosto:
            for kirja in self.__kirjat:
                tiedosto.write(
                    f"{kirja.id};{kirja.kirjoittaja};{kirja.nimi};{kirja.lainassa}\n")


        return kirja.id

    def lainaa(self, id):
        lainattava = None
        for kirja in self.__kirjat:
            if kirja.id == id:
                lainattava = kirja
        if lainattava == None or lainattava.lainassa:
            return False
        lainattava.lainassa = True
        
        with open("tiedosto.csv", "w") as tiedosto:
            for kirja in self.__kirjat:
                tiedosto.write(
                    f"{kirja.id};{kirja.kirjoittaja};{kirja.nimi};{kirja.lainassa}\n")

        return True

    def palauta(self, id):
        palautettava = None
        for kirja in self.__kirjat:
            if kirja.id == id:
                palautettava = kirja
        if palautettava == None or not palautettava.lainassa:
            return False
        palautettava.lainassa = False

        with open("tiedosto.csv", "w") as tiedosto:
            for kirja in self.__kirjat:
                tiedosto.write(
                    f"{kirja.id};{kirja.kirjoittaja};{kirja.nimi};{kirja.lainassa}\n")
      
        return True

    def hae_nimella(self, x):
        haetut = []
        for kirja in self.__kirjat:
            print(x.lower(), kirja.nimi.lower(),  x.lower() in kirja.nimi.lower())
            if x.lower() in kirja.nimi.lower():
                haetut.append(kirja)
        return haetut

    def hae_kirjoittajan_perusteella(self, x):
        loytyneet = []
        for kirja in self.__kirjat:
            if kirja.kirjoittaja == x:
                loytyneet.append(kirja)
        return loytyneet

    def hae_lainaamattomat(self):
        match = []
        for kirja in self.__kirjat:
            if not kirja.lainassa:
                match.append(kirja)
        return match

    def hae_lainatut(self):
        lainatut = []
        for kirja in self.__kirjat:
            if kirja.lainassa:
                lainatut.append(kirja)
        return lainatut

# seuraava on testipääohjelma, siihen ei tehtävässä kiinnitetä huomoita

kirjasto = Kirjasto()
lainatut = []
while True:
  print()
  print("1 näytä lainaamattomat")
  print("2 näytä lainatut")
  print("3 hae nimellä")
  print("4 hae kirjoittajan perusteella")
  print("5 lainaa")
  print("6 palauta")
  print("7 lisää kirja")
  komento = input("komento: ")
  print("")
  if komento=="1":
      for kirja in kirjasto.hae_lainaamattomat():
          print(kirja)
  elif komento=="2":
      for kirja in kirjasto.hae_lainatut():
          print(kirja)
  elif komento=="3":
      hakusana = input("nimi: ")  
      for kirja in kirjasto.hae_nimella(hakusana):
          print(kirja)      
  elif komento=="4":
      hakusana = input("kirjailija: ")  
      for kirja in kirjasto.hae_kirjoittajan_perusteella(hakusana):
          print(kirja) 
  elif komento=="5": 
      id = input("lainattavan id: ") 
      status = kirjasto.lainaa(int(id))
      print("onnistuiko ", status)
  elif komento=="6": 
      id = input("palautettavan id: ")
      status = kirjasto.palauta(int(id))
      print("onnistuiko ", status)
  elif komento=="7": 
      nimi = input("kirjan nimi:  ")  
      kirjoittaja = input("kirjoittaja:  ")  
      kirjasto.lisaa(kirjoittaja, nimi)
  else:
      break