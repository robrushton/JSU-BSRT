CREATE TABLE Role (
    RoleID BIGINT NOT NULL AUTO_INCREMENT,
    RoleName VARCHAR(20) NOT NULL,
    CreatedOn DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (RoleID)
);

CREATE TABLE Users (
    UserID BIGINT NOT NULL AUTO_INCREMENT,
    UserEmail VARCHAR(100) NOT NULL,
    UserPWHash VARCHAR(64) NOT NULL,
    UserSalt VARCHAR(64) NOT NULL,
    UserRole BIGINT NOT NULL,
    UserPsychMajor BOOLEAN NOT NULL,
    UserPsychMinor BOOLEAN NOT NULL,
    CreatedOn DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (UserID),
    FOREIGN KEY (UserRole) REFERENCES Role(RoleID)
);

CREATE TABLE Research (
    ResearchID BIGINT NOT NULL AUTO_INCREMENT,
    ResearchName VARCHAR(100) NOT NULL,
    ResearchFacilitator BIGINT NOT NULL,
    ResearchDescription VARCHAR(500) NOT NULL,
    ResearchCredits INT NOT NULL,
    IsVisible BOOLEAN DEFAULT TRUE,
    IsDeleted BOOLEAN DEFAULT FALSE,
    CreatedOn DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ResearchID),
    FOREIGN KEY (ResearchFacilitator) REFERENCES Users(UserID)
);

CREATE TABLE ResearchSlot (
    ResearchSlotID BIGINT NOT NULL AUTO_INCREMENT,
    ResearchID BIGINT NOT NULL,
    ResearchSlotOpenings INT NOT NULL,
    StartTime DATETIME NOT NULL,
    EndTime DATETIME NOT NULL,
    CreatedOn DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ResearchSlotID),
    FOREIGN KEY (ResearchID) REFERENCES Research(ResearchID)
);

CREATE TABLE StudentResearch (
    StudentResearchID BIGINT NOT NULL AUTO_INCREMENT,
    UserID BIGINT NOT NULL,
    ResearchSlotID BIGINT NOT NULL,
    IsCompleted BOOLEAN DEFAULT FALSE,
    CreatedOn DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (StudentResearchID),
    FOREIGN KEY (UserID) REFERENCES Users(UserID),
    FOREIGN KEY (ResearchSlotID) REFERENCES ResearchSlot(ResearchSlotID)
);

INSERT INTO Role(RoleName) VALUES ('student'), ('professor'), ('admin');

INSERT INTO Users(UserEmail, UserPWHash, UserSalt, UserRole, UserPsychMajor, UserPsychMinor)
VALUES ('stu1@test.com', 'ff8e3b172b653590bddb8844a2a36bfde5c85286c1a18b1b9c42aadd44f7f6f0', '93d8594284ab6c719f4efc49f92df34dab0d27595897fa87b9153f2996bace38', 1, TRUE, FALSE),
('stu2@test.com', '33e3f623d454eb60ebf4b78f4ffdf19afeb18b97440758c492ab4bff00c2af18', 'aefe69d8380ac59b0d905acc057448d7d9b139924e88eb316c18dfdf59421e37', 1, FALSE, TRUE),
('stu3@test.com', '15456f2bf9615599e75a9a7efdf92bf4eeb5c0fc5851253ede0978211486bcfa', 'e62bf146cca5550383763acc9773bd7d6dfa7cdaa917695ea60fe9da5066237a', 1, FALSE, FALSE),
('prof1@test.com', 'aaa428006ae5412e3ec4f85b060aab1e6bf2f8cf92f210db082f8f54dde2044f', 'cca227b5b7991554991c1593f324a5f27e855e1a99111fc85587d678daa7910f', 2, FALSE, FALSE),
('prof2@test.com', '801dd5ab3a988274536f5cbf3ed8e20d882c206c988e9a801f21ae45b741dc0b', '935367ad577df4f67dac49dd3d4fa810d16cd65fc93238578145e7d3b1ad6b76', 2, FALSE, FALSE),
('admin@test.com', '175600bc24a890859cba3223858b25720da92057c35bad85532c47319d22bbab', 'e95ebd623fa6a2dfade14ac2559bfc3874fd850b5210e33f57469559ad24b2fa', 3, FALSE, FALSE);

INSERT INTO Research(ResearchName, ResearchFacilitator, ResearchDescription, ResearchCredits, IsVisible, IsDeleted)
VALUES ('Research One', 4, 'This is example project number 1', 2, TRUE, FALSE),
('Research Two', 5, 'This is example project number 2', 3, TRUE, FALSE),
('Research Three', 4, 'This is example project number 3', 1, TRUE, FALSE),
('Research Four', 5, 'This is example project number 4', 2, TRUE, FALSE),
('Research Five', 4, 'This is example project number 5', 3, TRUE, FALSE),
('Research Six', 5, 'This is example project number 6', 1, TRUE, FALSE),
('Research Seven', 4, 'This is example project number 7', 2, TRUE, FALSE),
('Research Eight', 5, 'This is example project number 8', 3, TRUE, FALSE),
('Research Nine', 4, 'This is example project number 9', 1, FALSE, FALSE),
('Research Ten', 5, 'This is example project number 10', 2, FALSE, TRUE);

INSERT INTO ResearchSlot(ResearchID, ResearchSlotOpenings, StartTime, EndTime)
VALUES (1, 5, '2017-8-28 13:00:00', '2017-8-28 13:00:00'),
(1, 10, '2017-8-29 13:00:00', '2017-8-29 13:00:00'),
(2, 5, '2017-9-28 15:30:00', '2017-9-28 16:30:00'),
(3, 10, '2017-10-28 15:30:00', '2017-10-28 16:30:00'),
(3, 5, '2017-10-29 15:30:00', '2017-10-29 15:30:00'),
(4, 10, '2017-11-28 08:00:00', '2017-11-28 10:00:00'),
(5, 5, '2017-12-28 10:00:00', '2017-12-28 12:00:00');

INSERT INTO StudentResearch(UserID, ResearchSlotID, IsCompleted)
VALUES (1, 1, FALSE),
(1, 3, FALSE),
(2, 2, FALSE),
(2, 4, FALSE),
(2, 7, FALSE),
(3, 4, FALSE),
(3, 1, FALSE);
