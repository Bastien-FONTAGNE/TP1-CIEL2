const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const connection = require('./db')

const app = express();

//Paramètres servant au fonctionnement du serveur et de la sécurité de celui-ci
const port = 3000;
const jwtKey = "Key"
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100
});

//Utilisation des paramètres défini précedemment 
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(limiter);

//Route d'inscription via l'API
app.post('/register', (req, res) => {
    
    const {name, password} = req.body;
    if(!name || !password) return res.status(400).json({ message : "Le nom d'utilisateur ou le mot de passe est manquant !" });
    
    const sqlVerif = `SELECT name FROM User WHERE name = ?`
    
    connection.query(sqlVerif, [name], (err, result) => {
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
                    
                    let token = jwt.sign({ name }, jwtKey);
                    
                    const sqlNewUser = `INSERT INTO User (name, password, token) VALUES (?, ?, ?)`;
                    
                    connection.query(sqlNewUser, [name, hashedPassword, token], (sqlErr) => {
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

//Route de connexion via l'API
app.post('/login', (req, res) => {
    const { name, password } = req.body;

    if(!name || !password) return res.status(400).json({ message: "Nom ou mot de passe manquant !" });

    const sqlLogin = 'SELECT password, token FROM User WHERE name = ?'

    connection.query(sqlLogin, [name], (err, result) => {
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
            let token = jwt.sign({ name }, jwtKey);

            connection.query(sqlLoginToken, [token, name], (err) => {
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
            res.status(409).json({ message : "Mot de pass incorrect"});
        }
    })
})

//Route de déconnexion via l'API
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

//Route par défaut pour envoyer la page principale
app.get('/', (req, res) => {
    res.sendFile('../index.html');
})

//Lancement du serveur sur un port défini
app.listen(port, () => {
    console.log(`Le serveur NodeJS est en écoute sur le port ${port}`);
})