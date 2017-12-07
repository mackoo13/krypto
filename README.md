# Kryptografia w Java Security
Zadanie dodatkowe z kryptografii

by mackoo13 + oswinoswin

## Kryptografia symetryczna

Generowanie klucza

```java GenKey [algorytm]```

Szyfrowanie

```java Encrypt [algorytm] [tryb: ecb/cbc] [padding] [nazwa pliku]```

Deszyfrowanie

```java Decrypt [algorytm] [tryb: ecb/cbc] [padding] [nazwa pliku]```

Program szyfrujący generuje plik o nazwie ```enc-[nazwa pliku]```. Uruchamiając program deszyfrujący podajemy ponownie nazwę pierwotnego pliku (bez przedrostka ```enc-```)!

Należy zwrócić uwagę na to, by programy były wywołane dla tego samego algorytmu i paddingu.

Dostępne algorytmy szyfrowania:
* Blowfish
* DES

Paddingi: 
* PKCS7
* ISO10126
* AnsiX923
* CiphertextStealing

## Kryptografia asymetryczna

Generowanie klucza

```java RSASaveKeys [długość klucza]```

Szyfrowanie

```java RSAEncrypt [nazwa pliku] [długość klucza]```

Deszyfrowanie

```java RSADecrypt [nazwa pliku] [długość klucza]```

Program szyfrujący generuje plik o nazwie ```RSA-enc-[nazwa pliku]```. Uruchamiając program deszyfrujący podajemy ponownie nazwę pierwotnego pliku (bez przedrostka ```RSA-enc-```)!

Klucze są wczytywane automatycznie z plików ```Public[długość klucza].pem``` i ```Private[długość klucza].pem```
