/**
 * Runs before React hydrates (see the root layout), as plain JavaScript text.
 *
 * 1. Applies the stored table density to <html>, so rows do not jump when the page loads.
 * 2. When the browser blocks storage (merely reading `window.localStorage` throws, as in some private windows or with
 *    site data blocked; a working store whose methods fail is left alone), installs an in-memory stand-in flagged `memory: true`. The layout library reads
 *    and writes `localStorage` without guarding it, so without this the whole dashboard fails to render.
 *    Netsight's own preferences ignore a memory stand-in (they report "could not save" instead).
 */
export const EARLY_SCRIPT = `(function(){
var d=document.documentElement,ls=null;
try{ls=window.localStorage}catch(e){}
if(ls){
try{if(ls.getItem('netsight.density')==='compact')d.dataset.density='compact'}catch(e){}
return;
}
var m=new Map();
try{Object.defineProperty(window,'localStorage',{configurable:true,value:{memory:true,
get length(){return m.size},
key:function(i){var k=Array.from(m.keys());return i>=0&&i<k.length?k[i]:null},
getItem:function(k){k=String(k);return m.has(k)?m.get(k):null},
setItem:function(k,v){m.set(String(k),String(v))},
removeItem:function(k){m.delete(String(k))},
clear:function(){m.clear()}}})}catch(e){}
})();`;
