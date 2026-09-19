-- 1. Creating the security tables
CREATE TABLE Roles(
RoleID INT PRIMARY KEY, RoleName VARCHAR(50) NOT NULL, ClearanceLevel INT NOT NULL);

CREATE TABLE Users(
UserID INT PRIMARY KEY,
    Username VARCHAR(50) UNIQUE NOT NULL,
    Department VARCHAR(50),
    IsActive BOOLEAN DEFAULT TRUE
);

CREATE TABLE UserRoles (
    UserID INT,
    RoleID INT,
    AssignedDate DATE,
    FOREIGN KEY (UserID) REFERENCES Users(UserID),
    FOREIGN KEY (RoleID) REFERENCES Roles(RoleID),
    PRIMARY KEY (UserID, RoleID)
);

CREATE TABLE SecurityAuditLogs (
    LogID INT PRIMARY KEY AUTO_INCREMENT,
    AttemptedUsername VARCHAR(50),
    LoginTime DATETIME,
    LoginStatus VARCHAR(20), -- 'SUCCESS' or 'FAILED'
    IPAddress VARCHAR(15)
);

-- 2. Insert baseline data to simulate a corporate environment
INSERT INTO Roles (RoleID, RoleName, ClearanceLevel) VALUES
(1, 'Admin', 99),
(2, 'Security Analyst', 75),
(3, 'Standard User', 10);

INSERT INTO Users (UserID, Username, Department) VALUES
(101, 'J_Smith', 'HR'),
(102, 'A_Scatlow_Sec', 'IT_Security'),
(103, 'B_Guest', 'Contractor');

INSERT INTO UserRoles (UserID, RoleID, AssignedDate) VALUES
(101, 3, '2025-01-15'),
(102, 1, '2025-06-10'), 
(103, 3, '2026-02-01');

INSERT INTO SecurityAuditLogs (AttemptedUsername, LoginTime, LoginStatus, IPAddress) VALUES
('J_Smith', '2026-09-18 08:00:00', 'SUCCESS', '192.168.1.50'),
('B_Guest', '2026-09-18 09:15:00', 'FAILED', '10.0.0.99'),
('B_Guest', '2026-09-18 09:15:05', 'FAILED', '10.0.0.99'),
('B_Guest', '2026-09-18 09:15:10', 'FAILED', '10.0.0.99');

-- 3. CYBERSECURITY QUERY: Detect Potential Brute-Force Attacks
-- This query identifies IP addresses with more than 2 failed login attempts in our logs.
SELECT 
    IPAddress, 
    AttemptedUsername, 
    COUNT(*) as FailedAttempts,
    MAX(LoginTime) as LastAttempt
FROM SecurityAuditLogs
WHERE LoginStatus = 'FAILED'
GROUP BY IPAddress, AttemptedUsername
HAVING COUNT(*) > 2;

-- 4. CYBERSECURITY QUERY: Access Privilege Audit
-- This query lists all active users and their security clearance levels to ensure no excessive privileges.
SELECT 
    u.Username, 
    u.Department, 
    r.RoleName, 
    r.ClearanceLevel
FROM Users u
JOIN UserRoles ur ON u.UserID = ur.UserID
JOIN Roles r ON ur.RoleID = r.RoleID
WHERE u.IsActive = TRUE
ORDER BY r.ClearanceLevel DESC;)