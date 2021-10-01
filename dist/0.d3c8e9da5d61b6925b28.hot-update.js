exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 6:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const common_1 = __webpack_require__(7);
const config_1 = __webpack_require__(8);
const mongoose_1 = __webpack_require__(9);
const app_controller_1 = __webpack_require__(10);
const app_service_1 = __webpack_require__(11);
const auth_module_1 = __webpack_require__(12);
const cars_module_1 = __webpack_require__(30);
const mongoose = __webpack_require__(18);
const comment_module_1 = __webpack_require__(36);
mongoose.set('useFindAndModify', false);
let AppModule = class AppModule {
};
AppModule = __decorate([
    common_1.Module({
        imports: [
            config_1.ConfigModule.forRoot(),
            mongoose_1.MongooseModule.forRoot('mongodb://mongodb:3000/DB', {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                useCreateIndex: true,
            }),
            auth_module_1.AuthModule,
            cars_module_1.CarsModule,
            comment_module_1.CommentsModule,
        ],
        controllers: [app_controller_1.AppController],
        providers: [app_service_1.AppService],
    })
], AppModule);
exports.AppModule = AppModule;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ "use strict";
/******/ 
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("f4ab6a60969f9873bdb7")
/******/ })();
/******/ 
/******/ }
;