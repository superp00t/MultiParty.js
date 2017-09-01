import { MultiParty } from "./";
import * as CryptoJS from "crypto-js";

window["CryptoJS"] = CryptoJS
window["MultiParty"] = MultiParty;
window["BigInt"] = require("./lib/BigInt.js");
