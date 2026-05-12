# DGA_watchdog

Détection de domaines générés par DGA (RandomForest n-grammes) intégré à un moteur pour déceler les bursts sur une fenêtre temporelle

## DGA: explication de la menace

Un Domain Generation Algorithm est un algorithme généralement embarqué dans un malware qui lui permet de générer chaque jour des noms de domaines à partir d'une graine. De son côté, l'opérateur du malware dispose également du même algorithme et la même seed afin de générer les mêmes domaines. Lorsque le malware veut contacter son C2, il génère les domaines qui pour la plupart ne sont pas enregistrés (NXDOMAIN). Il suffit à l'opérateur de n'en enregistrer qu'une partie (un ou deux) afin de communiquer avec son malware et de masquer le domaine utilisé parmi la quantité de domaines générés pour lesquels une requête DNS a été faite.
Chaque jour, le malware génère de nouveaux domaines afin d'échapper à la détection et continuer à communiquer même si le domaine de la veille a été bloqué.

## Méthode de détection

### RandomForest

Développement d'un modèle RandomForest à 100 arbres entraîné sur des TF-IDF de character n-grammes (bigrammes, tigrammes, quadigrammes) atteignant AUC 0.96.

### Intégration du modèle dans un moteur

Détecter un DGA n'implique pas de mettre en lumière une communication d'un malware vers son C2. Il existe de nombreux domaines générés par DGA et pourtant légitimes (CDN, loadbalancers, tracking, UUIDs).
Ainsi, de part la mécanique de fonctionnement des malwares qui utilisent DGA, plutôt que de détecter un domaine DGA unique, on cherche à détecter un burst de résolution DNS dans une fenêtre temporelle donnée, par exemple plus de 50 domaines issus d'une IP source unique en 5 minutes.

