import { io } from 'socket.io-client';

export const socket = io('https://linkspace-lxa7.onrender.com', {
    transports: ['websocket'], // optional but recommended
});
