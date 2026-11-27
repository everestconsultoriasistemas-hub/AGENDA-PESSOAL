self.addEventListener('install',function(){self.skipWaiting()});
self.addEventListener('activate',function(e){e.waitUntil(self.clients.claim())});

/* Recebe o aviso do servidor mesmo com o app fechado */
self.addEventListener('push',function(e){
  var d={};try{d=e.data.json()}catch(x){}
  e.waitUntil(self.registration.showNotification(d.title||'Minha Agenda',{
    body:d.body||'',icon:'icon-192.png',badge:'icon-192.png',
    tag:d.tag||'agenda',renotify:true,requireInteraction:true,
    vibrate:[300,150,300],data:{url:'./'}}))
});

/* Tocar na notificação abre o app */
self.addEventListener('notificationclick',function(e){
  e.notification.close();
  e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(function(l){
    for(var i=0;i<l.length;i++){if('focus' in l[i])return l[i].focus()}
    return self.clients.openWindow('./')}))
});
