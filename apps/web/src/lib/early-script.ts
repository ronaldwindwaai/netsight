/**
 * Runs before React hydrates (see the root layout), as plain JavaScript text.
 *
 * 1. Applies the stored table density to <html>, so rows do not jump when the page loads.
 * 2. When the browser blocks storage (access to `localStorage` throws, as in some private windows or with
 *    site data blocked), installs an in-memory stand-in flagged `memory: true`. The layout library reads
 *    and writes `localStorage` without guarding it, so without this the whole dashboard fails to render.
 *    Netsight's own preferences ignore a memory stand-in (they report "could not save" instead).
 */
export const EARLY_SCRIPT = `(function(){
var d=document.documentElement;
try{
if(window.localStorage.getItem('netsight.density')==='compact')d.dataset.density='compact';
}catch(e){
var m={};
try{Object.defineProperty(window,'localStorage',{configurable:true,value:{memory:true,
getItem:function(k){return Object.prototype.hasOwnProperty.call(m,k)?m[k]:null},
setItem:function(k,v){m[k]=String(v)},
removeItem:function(k){delete m[k]},
clear:function(){m={}}}})}catch(e2){}
}
})();`;
