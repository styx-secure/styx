#!/usr/bin/env node
/* Independent APP-CORE-IFACE-0 JavaScript evidence adapter.
 *
 * This increment implements the ACV-066 reserved-reachability oracle only.
 * It deliberately does not claim to implement the complete interface evaluator.
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";


class AdapterFailure extends Error {}


function requireCondition(condition, message) {
  if (!condition) throw new AdapterFailure(message);
}


function readJson(filePath) {
  const stat = fs.lstatSync(filePath);
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), `invalid JSON authority: ${filePath}`);
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}


function exactKeys(value, expected, label) {
  requireCondition(value !== null && typeof value === "object" && !Array.isArray(value), `${label} is not an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  requireCondition(JSON.stringify(actual) === JSON.stringify(wanted), `${label} shape mismatch`);
}


function validateProfile(profile) {
  exactKeys(profile, ["applicationProfileId", "applicationProfileVersion", "styxProtocolVersion"], "profile");
  requireCondition(profile.applicationProfileId === "1", "profile id mismatch");
  requireCondition(profile.applicationProfileVersion === "1", "profile version mismatch");
  requireCondition(profile.styxProtocolVersion === "1", "Styx version mismatch");
}


const OBSERVATION_ENUMS = Object.freeze({
  transcriptVerification: ["VALID", "REJECTED"],
  referenceVerification: ["VALID", "REJECTED", "NOT_REACHED"],
  signatureVerification: ["VALID", "REJECTED", "NOT_EVALUATED"],
  suppliedLengthVerification: ["VALID", "REJECTED", "NOT_EVALUATED", "NOT_APPLICABLE"],
  commitmentVerification: ["VALID", "REJECTED", "PENDING", "NOT_PRESENT", "NOT_EVALUATED"],
  commitmentMatchVerification: ["VALID", "REJECTED", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate1: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate2: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate3: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate4: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate5: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate6: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate7: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
});


function validateObservations(observations) {
  exactKeys(observations, Object.keys(OBSERVATION_ENUMS), "transcript observations");
  for (const [name, allowed] of Object.entries(OBSERVATION_ENUMS)) {
    requireCondition(allowed.includes(observations[name]), `invalid transcript observation: ${name}`);
  }
}


function validateResponseShapeAndRelation(response, relations) {
  exactKeys(response, ["interfaceVersion", "operation", "profile", "result"], "response");
  requireCondition(response.interfaceVersion === "0", "interface version mismatch");
  validateProfile(response.profile);
  const result = response.result;
  if (response.operation === "VALIDATE_TRANSCRIPT") {
    exactKeys(result, ["kind", "reason", "stage", "observations"], "transcript result");
    validateObservations(result.observations);
  } else if (response.operation === "EVALUATE_GENESIS") {
    exactKeys(result, ["kind", "reason", "stage"], "genesis result");
  } else {
    throw new AdapterFailure("ACV-066 self-test received an unsupported operation");
  }
  const relationName = response.operation === "VALIDATE_TRANSCRIPT"
    ? "transcriptReasonStageRelationV0"
    : "genesisReasonStageRelationV0";
  const member = relations[relationName].some((row) => (
    row.kind === result.kind
      && (row.reason ?? null) === (result.reason ?? null)
      && row.stage === result.stage
  ));
  requireCondition(member, "response violates exact reason/stage relation");
}


function validateBeforeRelease(response, relations, reservedDetector = true) {
  validateResponseShapeAndRelation(response, relations);
  if (reservedDetector && (
    response.result.reason === "REFERENCE_MISMATCH"
      || response.result.observations?.referenceVerification === "REJECTED"
  )) {
    throw new AdapterFailure("APP-core v0 reserved reference mismatch was generated");
  }
  return response;
}


function referenceObservations() {
  return {
    commitmentMatchVerification: "NOT_APPLICABLE",
    commitmentVerification: "NOT_PRESENT",
    geometryPredicate1: "NOT_APPLICABLE",
    geometryPredicate2: "NOT_APPLICABLE",
    geometryPredicate3: "NOT_APPLICABLE",
    geometryPredicate4: "NOT_APPLICABLE",
    geometryPredicate5: "NOT_APPLICABLE",
    geometryPredicate6: "NOT_APPLICABLE",
    geometryPredicate7: "NOT_APPLICABLE",
    referenceVerification: "REJECTED",
    signatureVerification: "NOT_EVALUATED",
    suppliedLengthVerification: "NOT_APPLICABLE",
    transcriptVerification: "VALID",
  };
}


function containsPropertyName(node, propertyName) {
  if (Array.isArray(node)) return node.some((item) => containsPropertyName(item, propertyName));
  if (node === null || typeof node !== "object") return false;
  if (Object.prototype.hasOwnProperty.call(node.properties ?? {}, propertyName)) return true;
  return Object.values(node).some((item) => containsPropertyName(item, propertyName));
}


function selfTestAcv066(contractPath) {
  const schema = readJson(path.join(contractPath, "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json"));
  const relations = readJson(path.join(contractPath, "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"));
  const reserved = [
    ...relations.transcriptReasonStageRelationV0,
    ...relations.genesisReasonStageRelationV0,
  ].filter((row) => row.reachability === "RESERVED_UNREACHABLE_V0");
  requireCondition(JSON.stringify(reserved.map((row) => row.id).sort()) === JSON.stringify(["GRS-011", "TRS-011"]), "reserved relation closure drift");
  for (const name of ["ValidateTranscriptInputV0", "EvaluateGenesisInputV0"]) {
    requireCondition(!containsPropertyName(schema.$defs[name], "expectedReferenceHex"), `${name} selects an expected reference`);
  }

  const profile = {
    applicationProfileId: "1",
    applicationProfileVersion: "1",
    styxProtocolVersion: "1",
  };
  const transcriptReserved = {
    interfaceVersion: "0",
    operation: "VALIDATE_TRANSCRIPT",
    profile,
    result: {
      kind: "REJECTED",
      reason: "REFERENCE_MISMATCH",
      stage: "REFERENCE_DERIVATION",
      observations: referenceObservations(),
    },
  };
  const genesisReserved = {
    interfaceVersion: "0",
    operation: "EVALUATE_GENESIS",
    profile,
    result: {
      kind: "TERMINAL_NO_PROPOSAL",
      reason: "REFERENCE_MISMATCH",
      stage: "REFERENCE_DERIVATION",
    },
  };
  const observationReserved = {
    interfaceVersion: "0",
    operation: "VALIDATE_TRANSCRIPT",
    profile,
    result: {
      kind: "REJECTED",
      reason: "SIGNATURE_LENGTH_MISMATCH",
      stage: "SIGNATURE_VERIFICATION",
      observations: referenceObservations(),
    },
  };
  const fixtures = [transcriptReserved, genesisReserved, observationReserved];
  for (const fixture of fixtures) {
    validateResponseShapeAndRelation(fixture, relations);
    validateBeforeRelease(fixture, relations, false);
    let rejected = false;
    try {
      validateBeforeRelease(fixture, relations, true);
    } catch (error) {
      requireCondition(error instanceof AdapterFailure, "unexpected ACV-066 rejection");
      rejected = true;
    }
    requireCondition(rejected, "ACV-066 detector admitted a reserved response");
  }
  return {
    mutantAccepted: fixtures.length,
    normalRejected: fixtures.length,
    relationAccepted: fixtures.length,
    verdict: "PASS",
  };
}


function parseArguments(argv) {
  let selfTest = false;
  let contractPath = null;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--self-test-acv066") selfTest = true;
    else if (argv[index] === "--contract") contractPath = argv[++index];
    else throw new AdapterFailure(`unknown argument: ${argv[index]}`);
  }
  requireCondition(selfTest && contractPath, "--self-test-acv066 and --contract are required");
  return { contractPath };
}


try {
  const { contractPath } = parseArguments(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(selfTestAcv066(path.resolve(contractPath)))}\n`);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}
