class PalautetiedostonLukija:
    def lue_palautteet(self, nimi):
        """Lukee palautteet CSV-tiedostosta"""
        palautteet = []
        try:
            with open(nimi + ".csv") as tiedosto:
                for rivi in tiedosto:
                    osat = rivi.split(";")
                    palautteet.append({
                        "opiskelija": osat[0], 
                        "arvosana": int(osat[1]), 
                        "kommentti": osat[2]
                    })
        except:
            pass
        return palautteet
    
    def kirjoita_palaute(self, nimi, palautteet):
        with open(nimi + ".csv", "w") as tiedosto:
            for p in palautteet:
                tiedosto.write(f"{p['opiskelija']};{p['arvosana']};{p['kommentti']};\n")


# Strategy pattern
class PalautteenHakustrategia:
    def tayta_ehto(self, palaute):
        """Palauttaa True jos palaute täyttää ehdon"""
        raise NotImplementedError("Aliluokan tulee toteuttaa tayta_ehto-metodi")


class KommenttiStrategia(PalautteenHakustrategia):
    def tayta_ehto(self, palaute):
        return len(palaute["kommentti"]) > 0


class ArvosanaStrategia(PalautteenHakustrategia):
    def __init__(self, arvosana):
        self.arvosana = arvosana
    
    def tayta_ehto(self, palaute):
        return palaute["arvosana"] == self.arvosana


class ArvosanavaliStrategia(PalautteenHakustrategia):
    def __init__(self, min_arvosana, max_arvosana):
        self.min_arvosana = min_arvosana
        self.max_arvosana = max_arvosana
    
    def tayta_ehto(self, palaute):
        return palaute["arvosana"] >= self.min_arvosana and palaute["arvosana"] <= self.max_arvosana


class Kurssi:
    def __init__(self, nimi, vuosi):
        self.__nimi = nimi
        self.__vuosi = vuosi
        self.__palautteet = []

        # haetaan palautteet tiedostosta
        self._lukija = PalautetiedostonLukija()
        self.__palautteet = self._lukija.lue_palautteet(nimi)
    
    def _hae_kommentti(self, palaute_dict):
        """Apumetodi kommentin käsittelyyn"""
        return palaute_dict.get("kommentti", "")
    
    def _tallenna_tiedostoon(self):
        """Apumetodi palautteiden tallentamiseen"""
        self._lukija.kirjoita_palaute(self.__nimi, self.__palautteet)
    
    # lisätään uusi kurssipalaute, onnistuu vaan jos opiskelija ei ole antanut palautetta
    def anna_palaute(self, uusi_palaute):
        if self.hae_palaute(uusi_palaute["opiskelija"]):
            return False
        
        self.__palautteet.append({
            "opiskelija": uusi_palaute["opiskelija"], 
            "arvosana": uusi_palaute["arvosana"], 
            "kommentti": self._hae_kommentti(uusi_palaute)
        })

        self._tallenna_tiedostoon()
        return True
    
    def muuta_palautetta(self, muutettu_palaute):
        palaute = self.hae_palaute(muutettu_palaute["opiskelija"])
        if palaute:
            palaute["arvosana"] = muutettu_palaute["arvosana"]
            palaute["kommentti"] = self._hae_kommentti(muutettu_palaute)
            self._tallenna_tiedostoon()
            return True

        return False
    
    

    def hae_palaute(self, opiskelija):
        for palaute in self.__palautteet:
            if palaute["opiskelija"] == opiskelija:
                return palaute

        return None
    
    def _hae_palautteet_ehdolla(self, strategia):
        """Strategy pattern: yleinen metodi palautteiden hakemiseen strategialla"""
        palautteet = []
        for palaute in self.__palautteet:
            if strategia.tayta_ehto(palaute):
                palautteet.append(palaute)
        return palautteet
    
    def hae_kommentin_sisaltavat_palautteet(self):
        return self._hae_palautteet_ehdolla(KommenttiStrategia())

    def hae_palautteet_joiden_arvosana(self, x):
        return self._hae_palautteet_ehdolla(ArvosanaStrategia(x))

    def hae_palautteet_joiden_arvosana_valilla(self, x, y):
        return self._hae_palautteet_ehdolla(ArvosanavaliStrategia(x, y))
    

    def _laske_keskiarvo(self):
        """Laskee palautteiden keskiarvon"""
        if len(self.__palautteet) == 0:
            return 0
        summa = sum(palaute["arvosana"] for palaute in self.__palautteet)
        return summa / len(self.__palautteet)
    
    def _tulosta_otsikko(self):
        """Tulostaa yhteenvedon otsikon"""
        print(f"{self.__nimi}, {self.__vuosi}")
        print("============")
        print("palautteita annettiin", len(self.__palautteet), "kappaletta")
    
    def _tulosta_jakauma_rivi(self, arvosana):
        """Tulostaa yhden rivin arvosanajakaumasta"""
        print(f"{arvosana}: ", end="")
        for palaute in self.__palautteet:
            if palaute["arvosana"] == arvosana:
                print("*", end="")
        print()
    
    def _tulosta_jakauma(self):
        """Tulostaa arvosanajakauman"""
        print()
        print("jakauma")
        for i in range(5, 0, -1):
            self._tulosta_jakauma_rivi(i)
    
    def _tulosta_kommentit(self):
        """Tulostaa palautteiden kommentit"""
        print()
        print("kommentit")
        kommentin_sisaltavat = self.hae_kommentin_sisaltavat_palautteet()
        for palaute in kommentin_sisaltavat:
            print("  " + palaute["kommentti"])

    def yhteenveto(self):
        """Tulostaa kurssipalautteen yhteenvedon"""
        self._tulosta_otsikko()
        print("keskiarvo ", self._laske_keskiarvo())
        self._tulosta_jakauma()
        self._tulosta_kommentit()





# testipääohjelma
ohtu = Kurssi("ohtu", 2023)
ohtu.anna_palaute({ "opiskelija": "01234567", "arvosana": 4, "kommentti": "hyvät laskarit" })
ohtu.anna_palaute({ "opiskelija": "01234567", "arvosana": 2, "kommentti": "paska koe" })
ohtu.muuta_palautetta({ "opiskelija": "01234567", "arvosana": 2, "kommentti": "paska koe" })
ohtu.anna_palaute({ "opiskelija": "01231221", "arvosana": 4 })
ohtu.anna_palaute({ "opiskelija": "01234561", "arvosana": 3, "kommentti": "miniprojekti rocks" })
ohtu.anna_palaute({ "opiskelija": "01234111", "arvosana": 1 })

ohtu.yhteenveto()