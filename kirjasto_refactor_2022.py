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
    

class Tiedostokasittelija():
    def lue_tiedosto(self, tiedostonimi, kirjat, max_id):
        try:
          with open(tiedostonimi) as tiedosto:
            for rivi in tiedosto:
                  osat = rivi.rstrip().split(";")
                  id = int(osat[0])
                  kirja = Kirja(osat[1], osat[2], id, osat[3]=='True')
                  kirjat.append(kirja)
            max_id = 0
            for kirja in kirjat:
                    if kirja.id > max_id:
                        max_id = kirja.id
            return max_id +1
        except:
            pass

    def kirjoita_tiedostoon(self, tiedostonimi, kirjat):
        with open(tiedostonimi, "w") as tiedosto:
            for kirja in kirjat:
                tiedosto.write(
                    f"{kirja.id};{kirja.kirjoittaja};{kirja.nimi};{kirja.lainassa}\n")


# Strategy pattern: Kirjan tilan muuttaminen
class KirjanTilanMuutosStrategia:
    def onnistuu(self, kirja):
        """Tarkistaa, voidaanko operaatio suorittaa"""
        raise NotImplementedError("Aliluokan tulee toteuttaa onnistuu-metodi")
    
    def muuta_tilaa(self, kirja):
        """Suorittaa tilan muutoksen"""
        raise NotImplementedError("Aliluokan tulee toteuttaa suorita-metodi")


class LainausStrategia(KirjanTilanMuutosStrategia):
    def onnistuu(self, kirja):
        return not kirja.lainassa
    
    def muuta_tilaa(self, kirja):
        kirja.lainassa = True


class PalautusStrategia(KirjanTilanMuutosStrategia):
    def onnistuu(self, kirja):
        return kirja.lainassa
    
    def muuta_tilaa(self, kirja):
        kirja.lainassa = False


# tehtävässä tarkastaltava luokka
class Kirjasto:
    def __init__(self):
        self.__kirjat = []
        self.__id = 1
        self._tiedostokasittelija = Tiedostokasittelija()
        self.__id = self._tiedostokasittelija.lue_tiedosto("tiedosto.csv", self.__kirjat, self.__id)

    def lisaa(self, kirjoittaja, nimi):
        kirja = Kirja(kirjoittaja, nimi, self.__id)
        self.__id += 1
        self.__kirjat.append(kirja)

        self._tiedostokasittelija.kirjoita_tiedostoon("tiedosto.csv", self.__kirjat)

        return kirja.id
    
    def _hae_kirja(self, id):
        """Apumetodi kirjan hakemiseen ID:n perusteella"""
        for kirja in self.__kirjat:
            if kirja.id == id:
                return kirja
        return None
    
    def _muuta_kirjan_tilaa(self, id, strategia):
        """Strategy pattern: yleinen metodi kirjan tilan muuttamiseen"""
        kirja = self._hae_kirja(id)
        if kirja is None or not strategia.onnistuu(kirja):
            return False
        
        strategia.muuta_tilaa(kirja)
        self._tiedostokasittelija.kirjoita_tiedostoon("tiedosto.csv", self.__kirjat)
        return True
    
    def lainaa(self, id):
        return self._muuta_kirjan_tilaa(id, LainausStrategia())
    
    def palauta(self, id):
        return self._muuta_kirjan_tilaa(id, PalautusStrategia())
    
    def _hae_ehdolla(self, strategia):
        """Apumetodi kirjojen hakemiseen ehdolla"""
        loytyneet = []
        for kirja in self.__kirjat:
            if strategia.ehto_tayttyy(kirja):
                loytyneet.append(kirja)
        return loytyneet
    
    def hae_lainaamattomat(self):
        return self._hae_ehdolla(LainaamattomatStrategia())        

    def hae_lainatut(self):
        return self._hae_ehdolla(LainatutStrategia())        

    


    def hae_nimella(self, x):
        return self._hae_ehdolla(KirjanNimiStrategia(x))


    def hae_kirjoittajan_perusteella(self, x):
        return self._hae_ehdolla(KirjoittajanNimiStrategia(x))

   

class EhtoStrategia:
    def ehto_tayttyy(self, kirja):
        """Tarkistaa, täyttääkö kirja ehdon"""
        raise NotImplementedError("Aliluokan tulee toteuttaa ehto_tayttyy-metodi")    
    
class LainaamattomatStrategia(EhtoStrategia):
    def ehto_tayttyy(self, kirja):
        return not kirja.lainassa
    
class LainatutStrategia(EhtoStrategia):   
    def ehto_tayttyy(self, kirja):
        return kirja.lainassa
    
class KirjanNimiStrategia(EhtoStrategia):
    def __init__(self, nimi):
        self.nimi = nimi
    
    def ehto_tayttyy(self, kirja):
        return self.nimi.lower() in kirja.nimi.lower()
    
class KirjoittajanNimiStrategia(EhtoStrategia):
    def __init__(self, kirjoittaja):
        self.kirjoittaja = kirjoittaja
    
    def ehto_tayttyy(self, kirja):
        return self.kirjoittaja.lower() in kirja.kirjoittaja.lower()
    
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