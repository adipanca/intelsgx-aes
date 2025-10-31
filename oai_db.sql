-- phpMyAdmin SQL Dump
-- version 5.2.2
-- https://www.phpmyadmin.net/
--
-- Host: mysql:3306
-- Generation Time: Oct 31, 2025 at 06:20 AM
-- Server version: 8.0.43
-- PHP Version: 8.2.27

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `oai_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `AccessAndMobilitySubscriptionData`
--

CREATE TABLE `AccessAndMobilitySubscriptionData` (
  `ueid` varchar(15) NOT NULL,
  `servingPlmnid` varchar(15) NOT NULL,
  `supportedFeatures` varchar(50) DEFAULT NULL,
  `gpsis` json DEFAULT NULL,
  `internalGroupIds` json DEFAULT NULL,
  `sharedVnGroupDataIds` json DEFAULT NULL,
  `subscribedUeAmbr` json DEFAULT NULL,
  `nssai` json DEFAULT NULL,
  `ratRestrictions` json DEFAULT NULL,
  `forbiddenAreas` json DEFAULT NULL,
  `serviceAreaRestriction` json DEFAULT NULL,
  `coreNetworkTypeRestrictions` json DEFAULT NULL,
  `rfspIndex` int DEFAULT NULL,
  `subsRegTimer` int DEFAULT NULL,
  `ueUsageType` int DEFAULT NULL,
  `mpsPriority` tinyint(1) DEFAULT NULL,
  `mcsPriority` tinyint(1) DEFAULT NULL,
  `activeTime` int DEFAULT NULL,
  `sorInfo` json DEFAULT NULL,
  `sorInfoExpectInd` tinyint(1) DEFAULT NULL,
  `sorafRetrieval` tinyint(1) DEFAULT NULL,
  `sorUpdateIndicatorList` json DEFAULT NULL,
  `upuInfo` json DEFAULT NULL,
  `micoAllowed` tinyint(1) DEFAULT NULL,
  `sharedAmDataIds` json DEFAULT NULL,
  `odbPacketServices` json DEFAULT NULL,
  `serviceGapTime` int DEFAULT NULL,
  `mdtUserConsent` json DEFAULT NULL,
  `mdtConfiguration` json DEFAULT NULL,
  `traceData` json DEFAULT NULL,
  `cagData` json DEFAULT NULL,
  `stnSr` varchar(50) DEFAULT NULL,
  `cMsisdn` varchar(50) DEFAULT NULL,
  `nbIoTUePriority` int DEFAULT NULL,
  `nssaiInclusionAllowed` tinyint(1) DEFAULT NULL,
  `rgWirelineCharacteristics` varchar(50) DEFAULT NULL,
  `ecRestrictionDataWb` json DEFAULT NULL,
  `ecRestrictionDataNb` tinyint(1) DEFAULT NULL,
  `expectedUeBehaviourList` json DEFAULT NULL,
  `primaryRatRestrictions` json DEFAULT NULL,
  `secondaryRatRestrictions` json DEFAULT NULL,
  `edrxParametersList` json DEFAULT NULL,
  `ptwParametersList` json DEFAULT NULL,
  `iabOperationAllowed` tinyint(1) DEFAULT NULL,
  `wirelineForbiddenAreas` json DEFAULT NULL,
  `wirelineServiceAreaRestriction` json DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Table structure for table `Amf3GppAccessRegistration`
--

CREATE TABLE `Amf3GppAccessRegistration` (
  `ueid` varchar(15) NOT NULL,
  `amfInstanceId` varchar(50) NOT NULL,
  `supportedFeatures` varchar(50) DEFAULT NULL,
  `purgeFlag` tinyint(1) DEFAULT NULL,
  `pei` varchar(50) DEFAULT NULL,
  `imsVoPs` json DEFAULT NULL,
  `deregCallbackUri` varchar(50) NOT NULL,
  `amfServiceNameDereg` json DEFAULT NULL,
  `pcscfRestorationCallbackUri` varchar(50) DEFAULT NULL,
  `amfServiceNamePcscfRest` json DEFAULT NULL,
  `initialRegistrationInd` tinyint(1) DEFAULT NULL,
  `guami` json NOT NULL,
  `backupAmfInfo` json DEFAULT NULL,
  `drFlag` tinyint(1) DEFAULT NULL,
  `ratType` json NOT NULL,
  `urrpIndicator` tinyint(1) DEFAULT NULL,
  `amfEeSubscriptionId` varchar(50) DEFAULT NULL,
  `epsInterworkingInfo` json DEFAULT NULL,
  `ueSrvccCapability` tinyint(1) DEFAULT NULL,
  `registrationTime` varchar(50) DEFAULT NULL,
  `vgmlcAddress` json DEFAULT NULL,
  `contextInfo` json DEFAULT NULL,
  `noEeSubscriptionInd` tinyint(1) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Table structure for table `AuthenticationStatus`
--

CREATE TABLE `AuthenticationStatus` (
  `ueid` varchar(20) NOT NULL,
  `nfInstanceId` varchar(50) NOT NULL,
  `success` tinyint(1) NOT NULL,
  `timeStamp` varchar(50) NOT NULL,
  `authType` varchar(25) NOT NULL,
  `servingNetworkName` varchar(50) NOT NULL,
  `authRemovalInd` tinyint(1) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Table structure for table `AuthenticationSubscription`
--

CREATE TABLE `AuthenticationSubscription` (
  `UEID` varchar(255) NOT NULL,
  `authenticationMethod` varchar(25) NOT NULL,
  `encPermanentKey` varchar(255) DEFAULT NULL,
  `protectionParameterId` varchar(50) DEFAULT NULL,
  `sequenceNumber` json DEFAULT NULL,
  `authenticationManagementField` varchar(50) DEFAULT NULL,
  `algorithmId` varchar(50) DEFAULT NULL,
  `encOpcKey` varchar(50) DEFAULT NULL,
  `encTopcKey` varchar(50) DEFAULT NULL,
  `vectorGenerationInHss` tinyint(1) DEFAULT NULL,
  `n5gcAuthMethod` varchar(15) DEFAULT NULL,
  `rgAuthenticationInd` tinyint(1) DEFAULT NULL,
  `SUPI` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Dumping data for table `AuthenticationSubscription`
--

INSERT INTO `AuthenticationSubscription` (`UEID`, `authenticationMethod`, `encPermanentKey`, `protectionParameterId`, `sequenceNumber`, `authenticationManagementField`, `algorithmId`, `encOpcKey`, `encTopcKey`, `vectorGenerationInHss`, `n5gcAuthMethod`, `rgAuthenticationInd`, `SUPI`) VALUES
('0ed1eadb80c57745d2d39107d004cd07c0149a0c', '5G_AKA', 'LbZqd8Oa+HYFuJ6dASX/Q0DmvUV6z02LPZqEzn8UJR4Etn6msS7uehThxm6m3Xy9bzMB05owxl0F\nkw31', 'fec86ba6eb707ed08905757b1bb44b8f', '{\"sqn\": \"000000000000\", \"sqnScheme\": \"NON_TIME_BASED\", \"lastIndexes\": {\"ausf\": 0}}', '8000', 'milenage', 'C42449363BBAD02B66D16BC975D77CC1', NULL, NULL, NULL, NULL, '46iOUEfDdpnBp15UEHouvEozxoULrxhIAACojdHrfaC0VtuiwM7I4lHv7Q=='),
('a18c9fbcbb6b2f74559836d522c69a840545c1c4', '5G_AKA', '3u4zKo+F87nbS4Glfafy3O9ZVPyLax9rkBf39ImYiadCklTWJ4iv4VcdZWgeVM+IBE8B2N54Shtk\nWYQJ', 'fec86ba6eb707ed08905757b1bb44b8f', '{\"sqn\": \"000000000000\", \"sqnScheme\": \"NON_TIME_BASED\", \"lastIndexes\": {\"ausf\": 0}}', '8000', 'milenage', 'C42449363BBAD02B66D16BC975D77CC1', NULL, NULL, NULL, NULL, 'NAbXUNwxn/Yy+ixDP1MG6CmJ2NMWzzYK3/1GkgPmMb/9cxMC9zRM/e2ygw=='),
('ba078e7009115e56d54f4df31a455c7572878383', '5G_AKA', 'FxGJsM8iUCw735ty38NPOezkP5Bvw3JdogTNjAV2IJ1OVFiFV75noC8bbGcfM8cg1AMsVNR9/k9u\njSim', 'fec86ba6eb707ed08905757b1bb44b8f', '{\"sqn\": \"000000000000\", \"sqnScheme\": \"NON_TIME_BASED\", \"lastIndexes\": {\"ausf\": 0}}', '8000', 'milenage', 'C42449363BBAD02B66D16BC975D77CC1', NULL, NULL, NULL, NULL, 'Uui8TUuJKwo9demEdoOiByDMIr+ImIR+ZGfg2mAZYRfZi5FBwE6TketKHQ=='),
('d8439547ee45ef71ede3c039b9d932372740ad21', '5G_AKA', 'ubRr7IMyecuMojW8cvs+6FCQOZYY2S3XQYCGEYvt4jaH3e9QF5M+cG+Slpv+a2r6aDXQ9FDZyOHf\n0Gdr', 'fec86ba6eb707ed08905757b1bb44b8f', '{\"sqn\": \"000000000000\", \"sqnScheme\": \"NON_TIME_BASED\", \"lastIndexes\": {\"ausf\": 0}}', '8000', 'milenage', 'C42449363BBAD02B66D16BC975D77CC1', NULL, NULL, NULL, NULL, 'Wic50Ns0VJd+mmm+9VTcAmtsHhL9bddghQ1Lmond+jnhQD1Nn3e3n/PiWag=');

--
-- Triggers `AuthenticationSubscription`
--
DELIMITER $$
CREATE TRIGGER `AuthenticationSubscription_bi` BEFORE INSERT ON `AuthenticationSubscription` FOR EACH ROW BEGIN
  -- === UEID: simpan SHA1 sebagai 40-hex lowercase ===
  IF NEW.`UEID` IS NOT NULL THEN
    -- Jika sudah 40-hex, normalisasi ke lowercase
    IF CHAR_LENGTH(NEW.`UEID`) = 40
       AND NEW.`UEID` REGEXP '^[0-9A-Fa-f]{40}$' THEN
      SET NEW.`UEID` = LOWER(NEW.`UEID`);
    -- Jika 20-byte biner (jarang terjadi untuk VARCHAR), ubah ke hex
    ELSEIF OCTET_LENGTH(NEW.`UEID`) = 20 THEN
      SET NEW.`UEID` = LOWER(HEX(NEW.`UEID`));
    -- Selain itu, hash ke SHA1 (hasilnya 40-hex)
    ELSE
      SET NEW.`UEID` = LOWER(SHA1(NEW.`UEID`));
    END IF;
  END IF;

  -- === SUPI: AEAD -> Base64 simpan ke VARCHAR ===
  IF NEW.`SUPI` IS NOT NULL THEN
    SET NEW.`SUPI` = TO_BASE64(
      AEAD_ENCRYPT_DEFAULT(
        CAST(NEW.`SUPI` AS BINARY),
        CAST('tbl=AuthenticationSubscription;col=SUPI;v=1' AS BINARY),
        1
      )
    );
  END IF;

  -- === encPermanentKey: AEAD -> Base64 simpan ke VARCHAR ===
  IF NEW.`encPermanentKey` IS NOT NULL THEN
    SET NEW.`encPermanentKey` = TO_BASE64(
      AEAD_ENCRYPT_DEFAULT(
        CAST(NEW.`encPermanentKey` AS BINARY),
        CAST('tbl=AuthenticationSubscription;col=encPermanentKey;v=1' AS BINARY),
        1
      )
    );
  END IF;
END
$$
DELIMITER ;
DELIMITER $$
CREATE TRIGGER `AuthenticationSubscription_bu` BEFORE UPDATE ON `AuthenticationSubscription` FOR EACH ROW BEGIN
  -- === UEID: proses hanya jika berubah ===
  IF NEW.`UEID` IS NOT NULL AND (OLD.`UEID` IS NULL OR NEW.`UEID` <> OLD.`UEID`) THEN
    IF CHAR_LENGTH(NEW.`UEID`) = 40
       AND NEW.`UEID` REGEXP '^[0-9A-Fa-f]{40}$' THEN
      SET NEW.`UEID` = LOWER(NEW.`UEID`);
    ELSEIF OCTET_LENGTH(NEW.`UEID`) = 20 THEN
      SET NEW.`UEID` = LOWER(HEX(NEW.`UEID`));
    ELSE
      SET NEW.`UEID` = LOWER(SHA1(NEW.`UEID`));
    END IF;
  END IF;

  -- === SUPI: AEAD -> Base64 bila berubah ===
  IF NEW.`SUPI` IS NOT NULL AND (OLD.`SUPI` IS NULL OR NEW.`SUPI` <> OLD.`SUPI`) THEN
    SET NEW.`SUPI` = TO_BASE64(
      AEAD_ENCRYPT_DEFAULT(
        CAST(NEW.`SUPI` AS BINARY),
        CAST('tbl=AuthenticationSubscription;col=SUPI;v=1' AS BINARY),
        1
      )
    );
  END IF;

  -- === encPermanentKey: AEAD -> Base64 bila berubah ===
  IF NEW.`encPermanentKey` IS NOT NULL
     AND (OLD.`encPermanentKey` IS NULL OR NEW.`encPermanentKey` <> OLD.`encPermanentKey`) THEN
    SET NEW.`encPermanentKey` = TO_BASE64(
      AEAD_ENCRYPT_DEFAULT(
        CAST(NEW.`encPermanentKey` AS BINARY),
        CAST('tbl=AuthenticationSubscription;col=encPermanentKey;v=1' AS BINARY),
        1
      )
    );
  END IF;
END
$$
DELIMITER ;

-- --------------------------------------------------------

--
-- Table structure for table `SdmSubscriptions`
--

CREATE TABLE `SdmSubscriptions` (
  `ueid` varchar(15) NOT NULL,
  `subsId` int UNSIGNED NOT NULL,
  `nfInstanceId` varchar(50) NOT NULL,
  `implicitUnsubscribe` tinyint(1) DEFAULT NULL,
  `expires` varchar(50) DEFAULT NULL,
  `callbackReference` varchar(50) NOT NULL,
  `amfServiceName` json DEFAULT NULL,
  `monitoredResourceUris` json NOT NULL,
  `singleNssai` json DEFAULT NULL,
  `dnn` varchar(50) DEFAULT NULL,
  `subscriptionId` varchar(50) DEFAULT NULL,
  `plmnId` json DEFAULT NULL,
  `immediateReport` tinyint(1) DEFAULT NULL,
  `report` json DEFAULT NULL,
  `supportedFeatures` varchar(50) DEFAULT NULL,
  `contextInfo` json DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Table structure for table `SessionManagementSubscriptionData`
--

CREATE TABLE `SessionManagementSubscriptionData` (
  `ueid` varchar(15) NOT NULL,
  `servingPlmnid` varchar(15) NOT NULL,
  `singleNssai` json NOT NULL,
  `dnnConfigurations` json DEFAULT NULL,
  `internalGroupIds` json DEFAULT NULL,
  `sharedVnGroupDataIds` json DEFAULT NULL,
  `sharedDnnConfigurationsId` varchar(50) DEFAULT NULL,
  `odbPacketServices` json DEFAULT NULL,
  `traceData` json DEFAULT NULL,
  `sharedTraceDataId` varchar(50) DEFAULT NULL,
  `expectedUeBehavioursList` json DEFAULT NULL,
  `suggestedPacketNumDlList` json DEFAULT NULL,
  `3gppChargingCharacteristics` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Dumping data for table `SessionManagementSubscriptionData`
--

INSERT INTO `SessionManagementSubscriptionData` (`ueid`, `servingPlmnid`, `singleNssai`, `dnnConfigurations`, `internalGroupIds`, `sharedVnGroupDataIds`, `sharedDnnConfigurationsId`, `odbPacketServices`, `traceData`, `sharedTraceDataId`, `expectedUeBehavioursList`, `suggestedPacketNumDlList`, `3gppChargingCharacteristics`) VALUES
('001010000000001', '00101', '{\"sd\": \"FFFFFF\", \"sst\": 1}', '{\"ims\": {\"sscModes\": {\"defaultSscMode\": \"SSC_MODE_1\"}, \"sessionAmbr\": {\"uplink\": \"1000Mbps\", \"downlink\": \"1000Mbps\"}, \"5gQosProfile\": {\"5qi\": 2, \"arp\": {\"preemptCap\": \"NOT_PREEMPT\", \"preemptVuln\": \"PREEMPTABLE\", \"priorityLevel\": 15}, \"priorityLevel\": 1}, \"pduSessionTypes\": {\"defaultSessionType\": \"IPV4V6\"}}, \"oai\": {\"sscModes\": {\"defaultSscMode\": \"SSC_MODE_1\"}, \"sessionAmbr\": {\"uplink\": \"1000Mbps\", \"downlink\": \"1000Mbps\"}, \"5gQosProfile\": {\"5qi\": 6, \"arp\": {\"preemptCap\": \"NOT_PREEMPT\", \"preemptVuln\": \"PREEMPTABLE\", \"priorityLevel\": 15}, \"priorityLevel\": 1}, \"pduSessionTypes\": {\"defaultSessionType\": \"IPV4\"}, \"staticIpAddress\": [{\"ipv4Addr\": \"10.0.0.2\"}]}}', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
('001010000000002', '00101', '{\"sd\": \"FFFFFF\", \"sst\": 1}', '{\"ims\": {\"sscModes\": {\"defaultSscMode\": \"SSC_MODE_1\"}, \"sessionAmbr\": {\"uplink\": \"1000Mbps\", \"downlink\": \"1000Mbps\"}, \"5gQosProfile\": {\"5qi\": 2, \"arp\": {\"preemptCap\": \"NOT_PREEMPT\", \"preemptVuln\": \"PREEMPTABLE\", \"priorityLevel\": 15}, \"priorityLevel\": 1}, \"pduSessionTypes\": {\"defaultSessionType\": \"IPV4V6\"}}, \"oai\": {\"sscModes\": {\"defaultSscMode\": \"SSC_MODE_1\"}, \"sessionAmbr\": {\"uplink\": \"1000Mbps\", \"downlink\": \"1000Mbps\"}, \"5gQosProfile\": {\"5qi\": 6, \"arp\": {\"preemptCap\": \"NOT_PREEMPT\", \"preemptVuln\": \"PREEMPTABLE\", \"priorityLevel\": 15}, \"priorityLevel\": 1}, \"pduSessionTypes\": {\"defaultSessionType\": \"IPV4\"}, \"staticIpAddress\": [{\"ipv4Addr\": \"10.0.0.3\"}]}}', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
('001010000000003', '00101', '{\"sd\": \"FFFFFF\", \"sst\": 1}', '{\"ims\": {\"sscModes\": {\"defaultSscMode\": \"SSC_MODE_1\"}, \"sessionAmbr\": {\"uplink\": \"1000Mbps\", \"downlink\": \"1000Mbps\"}, \"5gQosProfile\": {\"5qi\": 2, \"arp\": {\"preemptCap\": \"NOT_PREEMPT\", \"preemptVuln\": \"PREEMPTABLE\", \"priorityLevel\": 15}, \"priorityLevel\": 1}, \"pduSessionTypes\": {\"defaultSessionType\": \"IPV4V6\"}}, \"oai\": {\"sscModes\": {\"defaultSscMode\": \"SSC_MODE_1\"}, \"sessionAmbr\": {\"uplink\": \"1000Mbps\", \"downlink\": \"1000Mbps\"}, \"5gQosProfile\": {\"5qi\": 6, \"arp\": {\"preemptCap\": \"NOT_PREEMPT\", \"preemptVuln\": \"PREEMPTABLE\", \"priorityLevel\": 15}, \"priorityLevel\": 1}, \"pduSessionTypes\": {\"defaultSessionType\": \"IPV4\"}, \"staticIpAddress\": [{\"ipv4Addr\": \"10.0.0.4\"}]}}', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL),
('001010000000004', '00101', '{\"sd\": \"FFFFFF\", \"sst\": 1}', '{\"ims\": {\"sscModes\": {\"defaultSscMode\": \"SSC_MODE_1\"}, \"sessionAmbr\": {\"uplink\": \"1000Mbps\", \"downlink\": \"1000Mbps\"}, \"5gQosProfile\": {\"5qi\": 2, \"arp\": {\"preemptCap\": \"NOT_PREEMPT\", \"preemptVuln\": \"PREEMPTABLE\", \"priorityLevel\": 15}, \"priorityLevel\": 1}, \"pduSessionTypes\": {\"defaultSessionType\": \"IPV4V6\"}}, \"oai\": {\"sscModes\": {\"defaultSscMode\": \"SSC_MODE_1\"}, \"sessionAmbr\": {\"uplink\": \"1000Mbps\", \"downlink\": \"1000Mbps\"}, \"5gQosProfile\": {\"5qi\": 6, \"arp\": {\"preemptCap\": \"NOT_PREEMPT\", \"preemptVuln\": \"PREEMPTABLE\", \"priorityLevel\": 15}, \"priorityLevel\": 1}, \"pduSessionTypes\": {\"defaultSessionType\": \"IPV4\"}, \"staticIpAddress\": [{\"ipv4Addr\": \"10.0.0.5\"}]}}', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `SmfRegistrations`
--

CREATE TABLE `SmfRegistrations` (
  `ueid` varchar(15) NOT NULL,
  `subpduSessionId` int NOT NULL,
  `smfInstanceId` varchar(50) NOT NULL,
  `smfSetId` varchar(50) DEFAULT NULL,
  `supportedFeatures` varchar(50) DEFAULT NULL,
  `pduSessionId` int NOT NULL,
  `singleNssai` json NOT NULL,
  `dnn` varchar(50) DEFAULT NULL,
  `emergencyServices` tinyint(1) DEFAULT NULL,
  `pcscfRestorationCallbackUri` varchar(50) DEFAULT NULL,
  `plmnId` json NOT NULL,
  `pgwFqdn` varchar(50) DEFAULT NULL,
  `epdgInd` tinyint(1) DEFAULT NULL,
  `deregCallbackUri` varchar(50) DEFAULT NULL,
  `registrationReason` json DEFAULT NULL,
  `registrationTime` varchar(50) DEFAULT NULL,
  `contextInfo` json DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Table structure for table `SmfSelectionSubscriptionData`
--

CREATE TABLE `SmfSelectionSubscriptionData` (
  `ueid` varchar(15) NOT NULL,
  `servingPlmnid` varchar(15) NOT NULL,
  `supportedFeatures` varchar(50) DEFAULT NULL,
  `subscribedSnssaiInfos` json DEFAULT NULL,
  `sharedSnssaiInfosId` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `AccessAndMobilitySubscriptionData`
--
ALTER TABLE `AccessAndMobilitySubscriptionData`
  ADD PRIMARY KEY (`ueid`,`servingPlmnid`) USING BTREE;

--
-- Indexes for table `Amf3GppAccessRegistration`
--
ALTER TABLE `Amf3GppAccessRegistration`
  ADD PRIMARY KEY (`ueid`);

--
-- Indexes for table `AuthenticationStatus`
--
ALTER TABLE `AuthenticationStatus`
  ADD PRIMARY KEY (`ueid`);

--
-- Indexes for table `AuthenticationSubscription`
--
ALTER TABLE `AuthenticationSubscription`
  ADD PRIMARY KEY (`UEID`),
  ADD KEY `idx_authsubscription_ueid` (`UEID`);

--
-- Indexes for table `SdmSubscriptions`
--
ALTER TABLE `SdmSubscriptions`
  ADD PRIMARY KEY (`subsId`,`ueid`) USING BTREE;

--
-- Indexes for table `SessionManagementSubscriptionData`
--
ALTER TABLE `SessionManagementSubscriptionData`
  ADD PRIMARY KEY (`ueid`,`servingPlmnid`) USING BTREE;

--
-- Indexes for table `SmfRegistrations`
--
ALTER TABLE `SmfRegistrations`
  ADD PRIMARY KEY (`ueid`,`subpduSessionId`) USING BTREE;

--
-- Indexes for table `SmfSelectionSubscriptionData`
--
ALTER TABLE `SmfSelectionSubscriptionData`
  ADD PRIMARY KEY (`ueid`,`servingPlmnid`) USING BTREE;

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `SdmSubscriptions`
--
ALTER TABLE `SdmSubscriptions`
  MODIFY `subsId` int UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
