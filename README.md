# TP1-CIEL2

Document Technique

Projet: création d’une page inscription/connexion
Chef de Projet: Quentin LAVAL
Responsable Technique: Bastien FONTAGNE					CIEL2
Développeur: Kevin LEMAIRE
I.Introduction

Ce document explique le fonctionnement et la structure de notre système d' inscription/connexion pour notre site web. Le site permet de s’inscrire, de se connecter et de se déconnecter.

Sommaire:


I.Introduction	2
2.Architecture	3
2.1.langage de programmation utilisé et technologie utilisé	3
2.2.Diagramme de l’architecture du site web	3
3.Fonctionnalité	3
3.1.Inscription	3
3.2.Connexion	5
3.3.Déconnexion	7
4.Sécurité	8
5.Base De Donnée	9
5.1.Représentation visuel	9
6.Tests	9
6.1.Tests de l’inscription/connexion	9
6.2.Test de la bdd	9
7.Déploiement	9
8.Conclusion	10




2.Architecture
2.1.langage de programmation utilisé et technologie utilisé

Frontend: html/css et Javascript

Backend: Node.js

BDD: mysql/mariadb et phpmyadmin

host du site web: sur la vm en n°219 (ip: 192.168.64.162) avec apache

Authentication: Token

2.2.Diagramme de l’architecture du site web






3.Fonctionnalité
3.1.Inscription

Route: /register

Méthode: POST

Code: //Route d'inscription via l'API
app.post('/register', (req, res) => {
   
    const {mail, name, password} = req.body;
    if(!mail || !name || !password) return res.status(400).json({ message : "Le nom d'utilisateur ou le mot de passe est manquant !" });
   
    const sqlVerif = `SELECT mail FROM User WHERE mail = ?`
   
    connection.query(sqlVerif, [mail], (err, result) => {
        if(err) {
            console.error("Erreur lors de la vérification d'inscription\nErreur SQL :\n",err);
            return res.status(500).json({ message: "Erreur lors de la création du compte" });
        }
       
        if(result.length === 0) {
            bcrypt.genSalt(10, (err, salt) => {
                if(err) {
                    console.error("Erreur lors de la génération du sel Bcrypt\nErreur Bcrpt Salt:\n",err);
                    return res.status(500).json({ message: "Erreur lors de la création du compte" });
                }
               
                bcrypt.hash(password, salt, (hashErr, hashedPassword) => {
                    if (hashErr) {
                        console.error('Erreur lors du hachage du mot de passe\nErreur Bcrypt Hash :\n', hashErr);
                        return res.status(500).json({ message: "Erreur lors de la création du compte" });
                    }
                   
                    let token = jwt.sign({ mail }, jwtKey);
                   
                    const sqlNewUser = `INSERT INTO User (mail, name, password, token) VALUES (?, ?, ?)`;
                   
                    connection.query(sqlNewUser, [mail, hashedPassword, token], (sqlErr) => {
                        if(sqlErr) {
                            console.error("Erreur lors de la création du nouvel User\nErreur sql :\n", sqlErr);
                            return res.status(500).json({ message : "Erreur lors de la création du compte" });
                        }
                        return res.status(200).json(
                            {
                                message: "Compte créé avec succès",
                                token: token
                            }
                        );
                    })
                })
            })
        } else {
            return res.status(409).json({ message : "Nom déjà utilisé "})
        }
    })
});


Traitement:
-vérifie si le mail ou le nom ou le mot de passe sont manquant
-vérifie si il y a eu des erreurs lors de l’inscription
-vérifie si le mot de passe a était hacher et si il y a eu une erreur dans sa génération
-vérifie si il y a eu une erreur dans la création du compte
-vérifie si le nom a déja était utiliser
-créer le compte

Réponse:
200: “Compte créé avec avec succés”
400: “Le nom d’utilisateur ou le mot de passe sont manquants”
409: “Nom déjà utilisé”
500: “Erreur lors de la création du compte


3.2.Connexion

route: /login

méthode: POST

code: //Route de connexion via l'API
app.post('/login', (req, res) => {
    const { mail, password } = req.body;


    if(!mail || !password) return res.status(400).json({ message: "Nom ou mot de passe manquant !" });


    const sqlLogin = 'SELECT password, token FROM User WHERE mail = ?'


    connection.query(sqlLogin, [mail], (err, result) => {
        if(err) {
            console.error("Erreur lors de la requête SQL login\nErreur sql :\n",err);
            return res.status(500).json({ message: "Erreur lors de la connexion" });
        }


        if(result.length === 0) {
            return res.status(409).json({ message: "Nom inconnu" });
        }


        const isPasswordValid = bcrypt.compareSync(password, result[0].password);


        if(isPasswordValid) {
            const sqlLoginToken = 'UPDATE User SET token = ? mail = ?'
            let token = jwt.sign({ mail }, jwtKey);


            connection.query(sqlLoginToken, [token, mail], (err) => {
                if(err) {
                    console.error("Erreur lors de la requête LoginToken\nErreur sql :\n", err);
                    return res.status(500).json({ message : " Erreur lors de la création du token"});
                }


                return res.status(200).json(
                    {
                        message : "Connexion Réussie",
                        token : token
                    }
                )
            })
        } else {
            res.status(409).json({ message : "Mot de passe incorrect"});
        }
    })
})


Traitement: 
-vérifie si le mail, le nom ou le mot de passe sont manquant
-vérifie si il y a une erreur durant la requête sql
-vérifie si le nom est dans la bdd
-vérifie le token de connexion

Réponse:
200: “Connexion Réussie”
400: “Nom d’utilisateur ou mot de passe manquant”
409: “Nom inconnu” ou “Mot de passe incorrect”
500: “Erreur lors de la connexion” ou “Erreur lors de la création du token”





3.3.Déconnexion

route: /disconnect

méthode: POST

code: //Route de déconnexion via l'API
app.post('/disconnect', (req, res) => {
    const {token} = req.body;


    if(!token) return res.status(400).json({ message: "Le token du User est requis pour la déconnexion"});


    const sqlDisconnect = 'UPDATE User SET token = NULL WHERE token = ?'


    connection.query(sqlDisconnect, [token], (err) => {
        if(err) {
            console.error("Erreur lors de la requête de déconnexion\n Erreur sql:\n", err);
            return res.status(500).json({ message : " Erreur lors de la déconnexion"});
        }
        return res.status(200).json({ message: " Utilisateur déconnecté"});
    })
})

Traitement: 
-vérifie si il il y a le token de l’utilisateur requis pour la déconnexion
-vérifie la requête de déconnexion

Réponse:
200: “Utilisateur déconnecté”
400: “Le token du User est requis pour la déconnexion”
500: “Erreur lors de la déconnexion”







4.Sécurité

cryptage du mot de passe: les mots de passe sont hachés en utilisant bcrypte

token: les token sont créer en utilisant JWT, ils ont une durée limité et ont une clé secréte

5.Base De Donnée 
5.1.Représentation visuel



6.Tests
6.1.Tests de l’inscription/connexion/déconnexion

Description
Critère d’acceptation
Résultat
1.Créer un compte
Le compte est créer avec un nom d’utilisateur, un e-mail et un mot de passe 


2.Se connecter au compte
On se connecte au compte en utilisant le nom d’utilisateur, le mail et le mot de passe associé


3.Se déconnecter du compte
On se déconnecte du compte







6.2.Test de la bdd


Description
Critère d’acceptation
Résultat
1.Création et stockage des donnès
On vérifie si les information de connexion sont bien stocker et crypter dans la bdd


2.Création du token
On vérifie si le compte est bien lier a un token















7.Déploiement

On déploie le site sur la vm pour tester l’application



8.Conclusion

Ce document technique montre comment implémenter et sécuriser le système d’inscription et de connexion pour le site web, ce dernier sera enrichi au fur et à mesure des projets.

